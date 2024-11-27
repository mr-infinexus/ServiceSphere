from flask import Flask, render_template, redirect, url_for, flash, request
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from sqlalchemy import or_
from sqlalchemy.orm import aliased
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config.from_object("application.config.Config")

db = SQLAlchemy(app)

import application.init_db
from application.models import User, Service, ServiceRequest, Review
from application.validations import LoginForm, CustomerForm, ProfessionalForm, EditServiceForm, BookServiceForm, RemarksForm, EditProfileForm


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/")
def home():
    flash("Welcome to ServiceSphere!", "info")
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password_hashed, form.password.data):
                login_user(user)
                if user.role == "admin":
                    flash("Logged in Successfully", "success")
                    return redirect(url_for("admin_home"))
                elif user.role == "customer" and user.status != "blocked":
                    flash("Logged in Successfully", "success")
                    return redirect(url_for("customer_home"))
                elif user.role == "professional":
                    if user.status == "verified":
                        flash("Logged in Successfully", "success")
                        return redirect(url_for("professional_home"))
                    elif user.status == "pending":
                        flash("Your profile is under verification", "info")
                        flash("Please try again after some time", "info")
                        return redirect(url_for("login"))
                    elif user.status == "blocked":
                        flash("You are not authorised anymore!", "danger")
                        return redirect(url_for("login"))
                else:
                    flash("Invalid role", "danger")
                    return redirect(url_for("login"))
            else:
                flash("Incorrect password.", "danger")
        else:
            flash("Incorrect username or password.", "danger")
    return render_template("login.html", form=form)


@app.route("/register/customer", methods=["GET", "POST"])
def register_customer():
    form = CustomerForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            flash("Username already exists!", "danger")
            return redirect(url_for("register_customer"))

        pwhash = generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password_hashed=pwhash, role="customer", status="verified",
                        fullname=form.fullname.data, address=form.address.data, pincode=form.pincode.data,
                        contact_number=form.contact_number.data)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("customers/c_register.html", form=form)


@app.route("/register/professional", methods=["GET", "POST"])
def register_professional():
    form = ProfessionalForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            flash("Username already exists!", "danger")
            return redirect(url_for("register_professional"))

        pwhash = generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password_hashed=pwhash, role="professional", status="pending",
                        fullname=form.fullname.data, service_type=form.service_type.data,
                        experience=form.experience.data, address=form.address.data, pincode=form.pincode.data,
                        contact_number=form.contact_number.data)
        db.session.add(new_user)
        db.session.commit()
        flash("Registration successful!", "success")
        flash("Please wait for admin verification.", "info")
        return redirect(url_for("login"))

    return render_template("professionals/p_register.html", form=form)


@app.route("/profile")
@login_required
def profile_details():
    return render_template("profile.html")


@app.route("/profile/edit", methods=["GET", "POST"])
@login_required
def edit_profile_details():
    form = EditProfileForm(obj=current_user)
    if form.validate_on_submit():
        current_user.fullname = form.fullname.data
        current_user.address = form.address.data
        current_user.pincode = form.pincode.data
        current_user.contact_number = form.contact_number.data
        db.session.commit()
        flash("Profile updated successfully.", "success")
        return redirect(url_for("profile_details"))
    return render_template("edit_profile.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out!", "info")
    return redirect(url_for("home"))


def role_required(role):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if current_user.role != role:
                flash(f"You are not supposed to be there, {current_user.username}!", "danger")
                if current_user.role == "admin":
                    return redirect(url_for("admin_home"))
                elif current_user.role == "customer":
                    return redirect(url_for("customer_home"))
                elif current_user.role == "professional":
                    return redirect(url_for("professional_home"))
                else:
                    return redirect(url_for("home"))
            return func(*args, **kwargs)
        return wrapper
    return decorator


# --------------------------------------------admin--------------------------------------------


@app.route("/admin")
@login_required
@role_required("admin")
def admin_home():
    professionals = User.query.filter_by(role="professional").all()
    services = Service.query.all()
    requests = ServiceRequest.query.all()
    avg_ratings = db.session.query(Review.professional_id, db.func.avg(Review.rating)).group_by(Review.professional_id)
    average_ratings_dict = dict(avg_ratings)
    return render_template("admin/a_home.html", users=professionals, services=services, requests=requests, average_ratings_dict=average_ratings_dict)


@app.route("/admin/service/add", methods=["GET", "POST"])
@login_required
@role_required("admin")
def add_service():
    form = EditServiceForm()
    if form.validate_on_submit():
        new_service = Service(
            name=form.name.data,
            price=form.price.data,
            time_required=form.time_required.data,
            description=form.description.data
        )
        db.session.add(new_service)
        db.session.commit()
        flash("Service added successfully!", "success")
        return redirect(url_for("admin_home"))
    return render_template("admin/a_edit_service.html", form=form, title_name="Add New")


@app.route("/admin/service/<int:service_id>/edit", methods=["POST"])
@login_required
@role_required("admin")
def edit_service(service_id):
    service = Service.query.get_or_404(service_id)
    form = EditServiceForm(obj=service)
    if form.validate_on_submit():
        service.name = form.name.data
        service.price = form.price.data
        service.time_required = form.time_required.data
        service.description = form.description.data
        db.session.commit()
        flash("Service updated successfully!", "success")
        return redirect(url_for("admin_home"))
    return render_template("admin/a_edit_service.html", form=form, service=service, title_name="Edit")


@app.route("/admin/service/<int:service_id>/delete", methods=["POST"])
@login_required
@role_required("admin")
def delete_service(service_id):
    service = Service.query.get_or_404(service_id)
    db.session.delete(service)
    db.session.commit()
    flash("Service and all associated professionals have been deleted successfully.", "success")
    return redirect(url_for("admin_home"))


@app.route("/admin/user/<int:user_id>")
@login_required
@role_required("admin")
def view_user_details(user_id):
    user = User.query.get_or_404(user_id)
    return render_template("admin/a_user_details.html", user=user)


@app.route("/admin/user/<int:user_id>/approve", methods=["POST"])
@login_required
@role_required("admin")
def approve_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.status != "verified":
        user.status = "verified"
        db.session.commit()
        flash("User approved successfully!", "success")
    else:
        flash("User is already approved.", "warning")
    return redirect(url_for("admin_home"))


@app.route("/admin/user/<int:user_id>/block", methods=["POST"])
@login_required
@role_required("admin")
def block_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.status != "blocked":
        user.status = "blocked"
        db.session.commit()
        flash("User blocked successfully!", "success")
    else:
        flash("User is already blocked.", "warning")
    return redirect(url_for("admin_home"))


@app.route("/admin/user/<int:user_id>/delete", methods=["POST"])
@login_required
@role_required("admin")
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash("User deleted successfully!", "success")
    return redirect(url_for("admin_home"))


@app.route("/admin/search", methods=["GET", "POST"])
@login_required
@role_required("admin")
def admin_search():
    requests, customers, professionals = [], [], []
    search_by = request.form.get("search_by")
    search_text = request.form.get("search_text", "").strip()
    if search_by == "service_request":
        Customer = aliased(User)
        Professional = aliased(User)
        requests = db.session.query(ServiceRequest, Customer, Professional, Service) \
            .join(Customer, Customer.id == ServiceRequest.customer_id) \
            .join(Professional, Professional.id == ServiceRequest.professional_id) \
            .join(Service, Service.id == ServiceRequest.service_id) \
            .filter(
                or_(ServiceRequest.service_status.ilike(f"%{search_text}%"),
                    ServiceRequest.time_of_request.ilike(f"%{search_text}%"),
                    ServiceRequest.time_of_completion.ilike(f"%{search_text}%"),
                    ServiceRequest.task.ilike(f"%{search_text}%"),
                    Customer.username.ilike(f"%{search_text}%"),
                    Customer.fullname.ilike(f"%{search_text}%"),
                    Professional.username.ilike(f"%{search_text}%"),
                    Professional.fullname.ilike(f"%{search_text}%"),
                    Service.name.ilike(f"%{search_text}%")
                )).order_by(ServiceRequest.time_of_request.desc()).all()
        if not requests:
            flash("No Service Requests found", "danger")
            return redirect(url_for("admin_search"))
    elif search_by == "customer":
        customers = User.query.filter(
            User.role == "customer",
            or_(User.username.ilike(f"%{search_text}%"),
                User.fullname.ilike(f"%{search_text}%")
            )).all()
        if not customers:
            flash("No Customer found", "danger")
            return redirect(url_for("admin_search")) 
    elif search_by == "professional":
        professionals = db.session.query(User, Service).join(User, User.service_type == Service.id).filter(
                User.role == "professional",
                or_(User.username.ilike(f"%{search_text}%"),
                    User.fullname.ilike(f"%{search_text}%"),
                    User.status.ilike(f"%{search_text}%"),
                    User.experience.ilike(f"%{search_text}%"),
                    Service.name.ilike(f"%{search_text}%")
                )).all()
        if not professionals:
            flash("No Service Professionals found", "danger")
            return redirect(url_for("admin_search"))
    return render_template("admin/a_search.html", requests=requests, customers=customers, professionals=professionals)


@app.route("/admin/summary")
@login_required
@role_required("admin")
def admin_summary():
    ratings_data = Review.query.group_by(Review.rating).with_entities(Review.rating, db.func.count()).all()
    rating_counts = dict(ratings_data)
    service_requests = ServiceRequest.query.all()
    service_counts = {"Requested": 0,"Accepted": 0, "Rejected": 0, "Closed": 0}
    for request in service_requests:
        if request.service_status == "requested":
            service_counts["Requested"] += 1
        elif request.service_status == "accepted":
            service_counts["Accepted"] += 1
        elif request.service_status == "rejected":
            service_counts["Rejected"] += 1
        elif request.service_status == "closed":
            service_counts["Closed"] += 1
    return render_template("admin/a_summary.html", rating_counts=rating_counts, service_counts=service_counts)


# -----------------------------------------customer--------------------------------------------


@app.route("/customer")
@login_required
@role_required("customer")
def customer_home():
    services = Service.query.all()
    service_history = ServiceRequest.query.join(Service, ServiceRequest.service_id == Service.id
                                                ).join(User, ServiceRequest.professional_id == User.id
                                                       ).order_by(ServiceRequest.time_of_request.desc()).all()
    return render_template("customers/c_home.html", services=services, service_history=service_history)


@app.route("/customer/<int:service_id>/select_professional")
@login_required
@role_required("customer")
def select_professional(service_id):
    professionals = User.query.filter(User.role == "professional", User.service_type == service_id, User.status == "verified").all()
    avg_ratings = db.session.query(Review.professional_id, db.func.avg(Review.rating)).group_by(Review.professional_id)
    average_ratings_dict = dict(avg_ratings)
    return render_template("customers/c_select_professional.html", professionals=professionals, average_ratings_dict=average_ratings_dict)


@app.route("/book/<int:service_id>/<int:professional_id>", methods=["POST"])
@login_required
@role_required("customer")
def book_service(service_id, professional_id):
    form = BookServiceForm()
    form.service_id.data = service_id
    form.professional_id.data = professional_id
    if form.validate_on_submit():
        new_entry = ServiceRequest(service_id=service_id, professional_id=professional_id,
                                   customer_id=current_user.id, service_status="requested", task=form.task.data)
        db.session.add(new_entry)
        db.session.commit()
        flash("Service booked successfully!", "success")
        return redirect(url_for("customer_home"))
    return render_template("customers/c_book_service.html", form=form, service_id=service_id, professional_id=professional_id)


@app.route("/close/<int:service_id>", methods=["POST"])
@login_required
@role_required("customer")
def close_service(service_id):
    history_entry = ServiceRequest.query.get_or_404(service_id)
    history_entry.service_status = "closed"
    db.session.commit()
    flash("Service closed successfully!", "success")
    return redirect(url_for("service_remarks", service_id=service_id))


@app.route("/remarks/<int:service_id>", methods=["GET", "POST"])
@login_required
@role_required("customer")
def service_remarks(service_id):
    history_entry = ServiceRequest.query.get_or_404(service_id)
    form = RemarksForm(obj=history_entry)
    if form.validate_on_submit():
        new_review = Review(
            service_request_id=history_entry.service_id,
            professional_id=history_entry.professional_id,
            customer_id=history_entry.customer_id,
            rating=form.rating.data,
            remarks=form.remarks.data
        )
        history_entry.time_of_completion = db.func.current_timestamp()
        db.session.add(new_review)
        db.session.commit()
        flash("Remarks submitted successfully!", "success")
        return redirect(url_for("customer_home"))
    return render_template("customers/c_remarks.html", form=form, service_id=service_id)


@app.route("/customer/search", methods=["GET", "POST"])
@login_required
@role_required("customer")
def customer_search():
    requests, professionals, average_ratings_dict = [], [], {}
    avg_ratings = db.session.query(Review.professional_id, db.func.avg(Review.rating)).group_by(Review.professional_id)
    search_by = request.form.get("search_by")
    search_text = request.form.get("search_text", "").strip()
    if search_by == "service_request":
        requests = db.session.query(ServiceRequest, User).join(User, User.id == ServiceRequest.professional_id).filter(
            ServiceRequest.customer_id == current_user.id,
            or_(ServiceRequest.service_status.ilike(f"%{search_text}%"),
                ServiceRequest.time_of_request.ilike(f"%{search_text}%"),
                ServiceRequest.time_of_completion.ilike(f"%{search_text}%"),
                ServiceRequest.task.ilike(f"%{search_text}%"),
                User.fullname.ilike(f"%{search_text}%")
                )).order_by(ServiceRequest.time_of_request.desc()).all()
        if not requests:
            flash("No Results found", "danger")
            return redirect(url_for("customer_search"))
    elif search_by == "professionals":
        professionals = db.session.query(User, Service).join(User, User.service_type == Service.id).filter(
                User.role == "professional",
                User.status == "verified",
                or_(User.fullname.ilike(f"%{search_text}%"),
                    User.address.ilike(f"%{search_text}%"),
                    User.pincode.ilike(f"%{search_text}%"),
                    User.contact_number.ilike(f"%{search_text}%"),
                    User.experience.ilike(f"%{search_text}%"),
                    Service.name.ilike(f"%{search_text}%")
                )).all()
        if not professionals:
            flash("No Service Professionals found", "danger")
            return redirect(url_for("customer_search"))
        average_ratings_dict = dict(avg_ratings)
    return render_template("customers/c_search.html", requests=requests, professionals=professionals, average_ratings_dict=average_ratings_dict)


@app.route("/customer/summary")
@login_required
@role_required("customer")
def customer_summary():
    service_requests = ServiceRequest.query.filter_by(customer_id=current_user.id).all()
    service_counts = {"Requested": 0, "Accepted": 0, "Rejected": 0, "Closed": 0}
    for request in service_requests:
        if request.service_status == "requested":
            service_counts["Requested"] += 1
        elif request.service_status == "accepted":
            service_counts["Accepted"] += 1
        elif request.service_status == "rejected":
            service_counts["Rejected"] += 1
        elif request.service_status == "closed":
            service_counts["Closed"] += 1
    return render_template("customers/c_summary.html", service_counts=service_counts)


# ----------------------------------------professional-----------------------------------------


@app.route("/professional")
@login_required
@role_required("professional")
def professional_home():
    today_services = ServiceRequest.query.join(User, User.id == ServiceRequest.customer_id).filter(
        ServiceRequest.professional_id == current_user.id,
        ServiceRequest.service_status == "requested").all()
    ongoing_services = ServiceRequest.query.join(User, User.id == ServiceRequest.customer_id).filter(
        ServiceRequest.professional_id == current_user.id,
        ServiceRequest.service_status == "accepted").all()
    closed_services = ServiceRequest.query.join(User, User.id == ServiceRequest.customer_id).filter(
        ServiceRequest.professional_id == current_user.id,
        or_(ServiceRequest.service_status == "rejected",
            ServiceRequest.service_status == "closed")).all()
    return render_template("professionals/p_home.html", today_services=today_services, ongoing_services=ongoing_services, closed_services=closed_services)


@app.route("/professional/accept_request/<int:request_id>", methods=["POST"])
@login_required
@role_required("professional")
def accept_request(request_id):
    request = ServiceRequest.query.get_or_404(request_id)
    if request.service_status != "requested":
        flash("This request is not in a pending state.", "info")
        return redirect(url_for("professional_home"))
    request.service_status = "accepted"
    db.session.commit()
    flash("Request accepted successfully.", "success")
    return redirect(url_for("professional_home"))


@app.route("/professional/reject_request/<int:request_id>", methods=["POST"])
@login_required
@role_required("professional")
def reject_request(request_id):
    request = ServiceRequest.query.get_or_404(request_id)
    if request.service_status != "requested":
        flash("This request is not in a pending state.", "info")
        return redirect(url_for("professional_home"))
    request.service_status = "rejected"
    db.session.commit()
    flash("Request rejected successfully.", "success")
    return redirect(url_for("professional_home"))


@app.route("/professional/search", methods=["GET", "POST"])
@login_required
@role_required("professional")
def professional_search():
    requests = []
    search_by = request.form.get("search_by")
    search_text = request.form.get("search_text", "").strip()
    if search_by == "service_request":
        requests = db.session.query(ServiceRequest, User).join(User, User.id == ServiceRequest.customer_id).filter(
            ServiceRequest.professional_id == current_user.id,
            or_(ServiceRequest.service_status.ilike(f"%{search_text}%"),
                ServiceRequest.time_of_request.ilike(f"%{search_text}%"),
                ServiceRequest.task.ilike(f"%{search_text}%"),
                User.username.ilike(f"%{search_text}%"),
                User.fullname.ilike(f"%{search_text}%"),
                User.address.ilike(f"%{search_text}%"),
                User.pincode.ilike(f"%{search_text}%")
                )).order_by(ServiceRequest.time_of_request.desc()).all()
        if not requests:
            flash("No Results found", "danger")
            return redirect(url_for("professional_search"))
    return render_template("professionals/p_search.html", requests=requests)


@app.route("/professional/summary")
@login_required
@role_required("professional")
def professional_summary():
    ratings_data = Review.query.filter_by(professional_id=current_user.id).group_by(Review.rating).with_entities(Review.rating, db.func.count()).all()
    rating_counts = dict(ratings_data)
    service_requests = ServiceRequest.query.filter_by(professional_id=current_user.id).all()
    service_counts = {"Requested": 0, "Accepted": 0, "Rejected": 0, "Closed": 0}
    for request in service_requests:
        if request.service_status == "requested":
            service_counts["Requested"] += 1
        elif request.service_status == "accepted":
            service_counts["Accepted"] += 1
        elif request.service_status == "rejected":
            service_counts["Rejected"] += 1
        elif request.service_status == "closed":
            service_counts["Closed"] += 1
    return render_template("professionals/p_summary.html", rating_counts=rating_counts, service_counts=service_counts)


if __name__ == "__main__":
    app.run()
