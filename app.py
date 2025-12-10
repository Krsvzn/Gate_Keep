from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from models import db, Resident, Visit
from models import db, Resident, Visit, PushSubscription, Unit, SystemSetting
from datetime import datetime
import json
from pywebpush import webpush, WebPushException
from models import PushSubscription
from functools import wraps
import re # For regex validation
from datetime import timedelta

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash("You do not have admin access.", "error")
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-for-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///gatekeep_pro.db'
app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=30)
# Initialize DB and Login Manager
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

VAPID_PRIVATE_KEY = "kdyzeqJxvufF3zSOKWGMtHXK8LIxHe_HZwNY7z4k8B8"
VAPID_CLAIMS = {"sub": "mailto:admin@gatekeep.com"}

def trigger_notification(resident_id, visitor_name):
    # Get all devices (subscriptions) for this resident
    subs = PushSubscription.query.filter_by(resident_id=resident_id).all()
    
    message_data = json.dumps({
        "title": "GateKeep Alert",
        "body": f"{visitor_name} is at the gate.",
        "url": "/dashboard"
    })

    for sub in subs:
        try:
            webpush(
                subscription_info={
                    "endpoint": sub.endpoint,
                    "keys": {"p256dh": sub.p256dh, "auth": sub.auth}
                },
                data=message_data,
                vapid_private_key=VAPID_PRIVATE_KEY,
                vapid_claims=VAPID_CLAIMS
            )
        except WebPushException as ex:
            # If the user revoked permission, delete the sub
            if ex.response.status_code == 410:
                db.session.delete(sub)
                db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return Resident.query.get(int(user_id))

# --- AUTHENTICATION FLOWS ---

# Replace the existing @app.route('/') in app.py with this:

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        block = request.form.get('block')
        if block: block = block.upper() # Safety check
        flat = request.form.get('flat')
        
        # NEW LOGIC: Join Resident and Unit tables
        # We find a resident whose Unit matches the block/flat entered
        resident = db.session.query(Resident).join(Unit).filter(
            Unit.block == block, 
            Unit.flat_number == flat
        ).first()

        if resident:
            # CASE 1: Resident found
            if resident.is_registered:
                return redirect(url_for('verify_password', user_id=resident.id))
            else:
                return redirect(url_for('claim_account', user_id=resident.id))
        else:
            # CASE 2: No Resident found, check if the Unit exists at all
            unit = Unit.query.filter_by(block=block, flat_number=flat).first()
            if unit:
                # Unit exists but is empty -> Allow Registration
                return redirect(url_for('register_new', block=block, flat=flat))
            else:
                # Unit does not exist in the system
                flash("This Unit does not exist. Contact Admin.")
                return redirect(url_for('login'))

    return render_template('login_start.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        block = request.form.get('block').upper()
        flat = request.form.get('flat')
        phone = request.form.get('phone')
        new_password = request.form.get('new_password')

        # 1. Find the resident based on Unit and Phone
        resident = db.session.query(Resident).join(Unit).filter(
            Unit.block == block,
            Unit.flat_number == flat,
            Resident.phone == phone
        ).first()

        # 2. Verify
        if resident:
            if len(new_password) < 6:
                flash("Password must be at least 6 characters.", "error")
            else:
                resident.set_password(new_password)
                db.session.commit()
                flash("Password reset successful! Please login.", "success")
                return redirect(url_for('login'))
        else:
            flash("Details do not match our records.", "error")
            
    return render_template('auth_forgot.html')

@app.route('/subscribe', methods=['POST'])
@login_required
def subscribe():
    data = request.get_json()
    
    # Check if subscription already exists to avoid duplicates
    existing = PushSubscription.query.filter_by(
        resident_id=current_user.id, 
        endpoint=data['endpoint']
    ).first()

    if not existing:
        new_sub = PushSubscription(
            resident_id=current_user.id,
            endpoint=data['endpoint'],
            p256dh=data['keys']['p256dh'],
            auth=data['keys']['auth']
        )
        db.session.add(new_sub)
        db.session.commit()
        
    return "Subscribed", 200

@app.route('/verify-password/<int:user_id>', methods=['GET', 'POST'])
def verify_password(user_id):
    resident = Resident.query.get_or_404(user_id)
    if request.method == 'POST':
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False # <--- NEW CHECK

        if resident.check_password(password):
            login_user(resident, remember=remember) # <--- PASS REMEMBER=TRUE
            
            # ISSUE 3 FIX: Redirect Admins directly to Admin Dashboard
            if resident.is_admin:
                return redirect(url_for('admin_dashboard'))
                
            return redirect(url_for('dashboard'))
        flash('Invalid Password')
    return render_template('auth_password.html', name=resident.name)

@app.route('/claim-account/<int:user_id>', methods=['GET', 'POST'])
def claim_account(user_id):
    """CASE 1: Pre-seeded user verifying identity"""
    resident = Resident.query.get_or_404(user_id)
    
    if request.method == 'POST':
        input_phone = request.form.get('phone')
        new_password = request.form.get('password')
        
        # Verify Phone against Pre-seeded Data
        if input_phone == resident.phone:
            resident.set_password(new_password)
            resident.is_registered = True
            db.session.commit()
            login_user(resident)
            return redirect(url_for('dashboard'))
        else:
            flash('Phone number does not match our records.')
            
    return render_template('auth_claim.html', resident=resident)

@app.route('/register-new/<block>/<flat>', methods=['GET', 'POST'])
def register_new(block, flat):
    # Find the Unit ID first
    unit = Unit.query.filter_by(block=block, flat_number=flat).first()
    if not unit:
        flash("This Flat Number does not exist in the building plan. Contact Admin.")
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form.get('name')
        phone = request.form.get('phone')
        password = request.form.get('password')

        # VALIDATION
        if not re.match(r"^[a-zA-Z\s]+$", name):
            flash("Name must contain only letters.")
            return redirect(request.url)
        if not re.match(r"^\d{10}$", phone):
            flash("Phone number must be exactly 10 digits.")
            return redirect(request.url)
        if len(password) < 6:
            flash("Password must be at least 6 characters.")
            return redirect(request.url)

        new_resident = Resident(unit_id=unit.id, name=name, phone=phone, is_registered=True)
        new_resident.set_password(password)
        db.session.add(new_resident)
        db.session.commit()
        login_user(new_resident)
        return redirect(url_for('dashboard'))
        
    return render_template('auth_register.html', block=block, flat=flat)

@app.route('/dashboard')
@login_required
def dashboard():
    # Fetch visits for this resident, sorted by newest first
    visits = Visit.query.filter_by(resident_id=current_user.id).order_by(Visit.id.desc()).all()
    
    # Check for expired visits
    for v in visits:
        if v.status == 'Pending' and v.is_expired:
            v.status = 'Expired'
            db.session.commit()

    return render_template('resident_dashboard.html', user=current_user, visits=visits)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))
# Add this inside app.py
# --- ADD THIS AFTER THE logout() FUNCTION ---

# 1. RESIDENT ACTION ROUTE (Approve/Deny)
@app.route('/respond/<int:visit_id>/<action>')
@login_required
def respond(visit_id, action):
    # Find the visit
    visit = Visit.query.get_or_404(visit_id)
    
    # Security Check: Ensure the logged-in user owns this visit
    if visit.resident_id != current_user.id:
        flash("Unauthorized access!", "error")
        return redirect(url_for('dashboard'))
    
    # Validate Action
    if action not in ['Approved', 'Denied']:
        flash("Invalid action.", "error")
        return redirect(url_for('dashboard'))

    # Update Status
    visit.status = action
    db.session.commit()
    
    flash(f"Visitor {action} successfully.", "success")
    return redirect(url_for('dashboard'))


# 2. GUARD DASHBOARD ROUTE

@app.route('/guard', methods=['GET', 'POST'])
def guard_dashboard():
    # Fetch Settings
    req_phone = SystemSetting.query.filter_by(key='req_visitor_phone').first()
    req_addr = SystemSetting.query.filter_by(key='req_visitor_addr').first()
    
    # Defaults if not set
    phone_setting = req_phone.value if req_phone else 'optional' 
    addr_setting = req_addr.value if req_addr else 'optional'

    if request.method == 'POST':
        block = request.form.get('block')
        flat = request.form.get('flat')
        visitor_name = request.form.get('visitor_name')
        visitor_phone = request.form.get('visitor_phone')
        visitor_addr = request.form.get('visitor_addr')
        purpose = request.form.get('purpose')

        # Backend Validation for Mandatory Fields
        if phone_setting == 'mandatory' and not visitor_phone:
            flash("Visitor Phone is mandatory.", "error")
            return redirect(request.url)
        
        # Check if Unit exists
        unit = Unit.query.filter_by(block=block, flat_number=flat).first()
        if unit and unit.residents:
            # Send to the first registered resident of that unit
            # (In a complex app, you'd select WHICH resident, but let's default to the first one)
            resident = unit.residents[0] 
            
            new_visit = Visit(
                visitor_name=visitor_name, 
                visitor_phone=visitor_phone,
                visitor_address=visitor_addr,
                purpose=purpose, 
                resident_id=resident.id,
                status='Pending'
            )
            db.session.add(new_visit)
            db.session.commit()
            trigger_notification(resident.id, visitor_name)
            flash(f"Request sent to {block}-{flat}", "success")
        else:
            flash("Flat empty or does not exist.", "error")
        return redirect(url_for('guard_dashboard'))

    # Inside guard_dashboard function in app.py
    recent_visits = db.session.query(Visit, Resident, Unit)\
    .select_from(Visit)\
    .join(Resident, Visit.resident_id == Resident.id)\
    .join(Unit, Resident.unit_id == Unit.id)\
    .order_by(Visit.id.desc())\
    .limit(20).all()
    
    return render_template('guard_panel.html', 
                           visits=recent_visits, 
                           settings={'phone': phone_setting, 'addr': addr_setting})

# API to check status updates without refreshing page (Poller)
@app.route('/api/visits')
def get_visits_api():
    recent_visits = db.session.query(Visit, Resident).join(Resident).order_by(Visit.id.desc()).limit(20).all()
    data = []
    for visit, resident in recent_visits:
        # Check expiry logic on the fly
        status = visit.status
        if visit.is_expired: 
             status = 'Expired'
        
        data.append({
            'id': visit.id,
            'visitor': visit.visitor_name,
            'flat': f"{resident.block}-{resident.flat_number}",
            'status': status,
            'time': visit.timestamp.strftime("%H:%M")
        })
    return {"visits": data}

# --- ADMIN ROUTES ---

@app.route('/admin')
@login_required
@admin_required
def admin_dashboard():
    # 1. Fetch Stats
    total_residents = Resident.query.count()
    total_visits = Visit.query.count()
    visits_today = Visit.query.filter(Visit.timestamp >= datetime.today().date()).count()
    
    # 2. Fetch ALL Logs (DataTables will handle pagination/sorting on frontend for now)
    # Inside admin_dashboard() function:

    # OLD LINE (Delete this):
    # logs = db.session.query(Visit, Resident, Unit).join(Resident).join(Unit).order_by(Visit.timestamp.desc()).all()

    # NEW EXPLICIT QUERY (Paste this):
    logs = db.session.query(Visit, Resident, Unit)\
        .select_from(Visit)\
        .join(Resident, Visit.resident_id == Resident.id)\
        .join(Unit, Resident.unit_id == Unit.id)\
        .order_by(Visit.timestamp.desc())\
        .all()
    
    # 3. Fetch Settings
    phone_setting = SystemSetting.query.filter_by(key='req_visitor_phone').first()
    addr_setting = SystemSetting.query.filter_by(key='req_visitor_addr').first()
    
    current_settings = {
        'phone': phone_setting.value if phone_setting else 'optional',
        'addr': addr_setting.value if addr_setting else 'optional'
    }

    return render_template('admin_dashboard.html', 
                           stats={'res': total_residents, 'vis': total_visits, 'today': visits_today},
                           logs=logs,
                           settings=current_settings)

@app.route('/admin/update-settings', methods=['POST'])
@login_required
@admin_required
def update_settings():
    # Helper to update or create setting
    def save_setting(key, val):
        setting = SystemSetting.query.filter_by(key=key).first()
        if not setting:
            setting = SystemSetting(key=key)
            db.session.add(setting)
        setting.value = val

    if request.form.get('action') == 'add_unit':
        # Logic to add a unit
        block = request.form.get('new_block')
        flat = request.form.get('new_flat')
        if not Unit.query.filter_by(block=block, flat_number=flat).first():
            db.session.add(Unit(block=block, flat_number=flat))
            db.session.commit()
            flash(f"Unit {block}-{flat} added.", "success")
        else:
            flash("Unit already exists.", "error")
            
    else:
        # Logic to update toggles
        save_setting('req_visitor_phone', request.form.get('req_visitor_phone'))
        save_setting('req_visitor_addr', request.form.get('req_visitor_addr'))
        db.session.commit()
        flash("Platform settings updated.", "success")

    return redirect(url_for('admin_dashboard'))

@app.route('/api/my-pending-requests')
@login_required
def check_pending_requests():
    # Count how many visits are 'Pending' for the current user
    pending_count = Visit.query.filter_by(resident_id=current_user.id, status='Pending').count()
    
    # Return JSON (True if count > 0, False otherwise)
    return {'has_new': pending_count > 0}

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)