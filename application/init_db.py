from app import app, db
from application.models import User, Service
from werkzeug.security import generate_password_hash

with app.app_context():
    db.create_all()

    if not User.query.filter_by(username='admin').first():
        pwhashed = generate_password_hash('adminIIT')
        admin = User(username='admin', password_hashed=pwhashed, role='admin',
                     status='verified', fullname='admin', address='admin', pincode=999999, contact_number=9999999999)
        db.session.add(admin)
        db.session.commit()

    if not Service.query.first():
        services = [
            Service(name='Appliance Repair Technician', price=1000, time_required=90),
            Service(name='Carpenter', price=1200, time_required=600),
            Service(name='Cleaner', price=500, time_required=50),
            Service(name='Electrician', price=2000, time_required=120),
            Service(name='Gardener', price=1000, time_required=190),
            Service(name='Handyman', price=800, time_required=60),
            Service(name='Home Security Consultant', price=5000, time_required=8),
            Service(name='Interior Designer', price=10000, time_required=90),
            Service(name='Laundry Service', price=100, time_required=30),
            Service(name='Painter', price=400, time_required=300),
            Service(name='Pest Control Specialist', price=660, time_required=90),
            Service(name='Plumber', price=550, time_required=50),
        ]
        db.session.add_all(services)
        db.session.commit()
