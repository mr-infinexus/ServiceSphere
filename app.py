from flask import Flask, render_template, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from sqlalchemy import func, or_, and_
from sqlalchemy.orm import aliased
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config.from_object("application.config.Config")

db = SQLAlchemy(app)

import application.init_db
from application.models import User, Service, ServiceRequest, Review
from application.validations import LoginForm, CustomerRegistrationForm, ProfessionalRegistrationForm, ServiceForm, BookServiceForm, RemarksForm, ProfileForm, EditProfileForm


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
                    else:
                        flash("You are not authorised!", "danger")
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
    form = CustomerRegistrationForm()
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
    form = ProfessionalRegistrationForm()
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
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for("login"))

    return render_template("professionals/p_register.html", form=form)


@app.route("/profile")
@login_required
def profile_details():
    form = ProfileForm(obj=current_user)
    return render_template("profile.html", form=form)


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
                # Redirect to their own role"s home page
                flash(f"You are not supposed to be there, {
                      current_user.username}!", "danger")
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


# ---------------------------------------admin----------------------------------------


@app.route("/admin")
@login_required
@role_required("admin")
def admin_home():
    professionals = User.query.filter_by(role="professional").all()
    services = Service.query.all()
    requests = ServiceRequest.query.all()
    avg_ratings = Review.query.with_entities(Review.professional_id, func.avg(
        Review.rating)).group_by(Review.professional_id).all()
    average_ratings_dict = dict()
    for result in avg_ratings:
        professional_id, avg_rating = result[0], result[1]
        average_ratings_dict[professional_id] = avg_rating
    for service_request in requests:
        professional_name = None
        if service_request.professional_id:
            professional = User.query.get(service_request.professional_id)
            professional_name = professional.fullname
        service_request.professional_name = professional_name
    return render_template("admin/a_home.html", users=professionals, services=services, requests=requests, average_ratings_dict=average_ratings_dict)


@app.route("/admin/service/add", methods=["GET", "POST"])
@login_required
@role_required("admin")
def add_service():
    form = ServiceForm()
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
    return render_template("admin/a_add_service.html", form=form)


@app.route("/admin/service/<int:service_id>/edit", methods=["POST"])
@login_required
@role_required("admin")
def edit_service(service_id):
    service = Service.query.get_or_404(service_id)
    form = ServiceForm(obj=service)
    if form.validate_on_submit():
        service.name = form.name.data
        service.price = form.price.data
        service.time_required = form.time_required.data
        service.description = form.description.data
        db.session.commit()
        flash("Service updated successfully!", "success")
        return redirect(url_for("admin_home"))
    return render_template("admin/a_edit_service.html", form=form, service=service)


@app.route("/admin/service/<int:service_id>/delete", methods=["POST"])
@login_required
@role_required("admin")
def delete_service(service_id):
    service = Service.query.get_or_404(service_id)
    db.session.delete(service)
    professionals = User.query.filter_by(
        service_type=service_id, role="professional").all()
    for professional in professionals:
        db.session.delete(professional)
    db.session.commit()
    flash("Service and all associated professionals have been deleted successfully.", "success")
    return redirect(url_for("admin_home"))


@app.route("/admin/user/<int:user_id>")
@login_required
@role_required("admin")
def view_user_details(user_id):
    user = User.query.get_or_404(user_id)
    service = Service.query.get(user.service_type)
    if user.role != "professional":
        return redirect(url_for("admin_home"))
    return render_template("admin/a_user_details.html", user=user, service=service)


@app.route("/admin/user/<int:user_id>/approve", methods=["POST"])
@login_required
@role_required("admin")
def approve_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.role == "professional" and user.status == "pending":
        user.status = "verified"
        db.session.commit()
        flash("User approved successfully!", "success")
    else:
        flash("User approval failed.", "danger")
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


@app.route('/admin/summary')
@login_required
@role_required("admin")
def admin_summary():
    ratings_data = Review.query.group_by(Review.rating).with_entities(
        Review.rating, db.func.count()).all()
    rating_counts = dict(ratings_data)
    service_requests = ServiceRequest.query.all()
    service_counts = {"Requested": 0,
                      "Accepted": 0, "Rejected": 0, "Closed": 0}
    for request in service_requests:
        if request.service_status == "requested":
            service_counts["Requested"] += 1
        elif request.service_status == "accepted":
            service_counts["Accepted"] += 1
        elif request.service_status == "rejected":
            service_counts["Rejected"] += 1
        elif request.service_status == "closed":
            service_counts["Closed"] += 1
    return render_template('admin/a_summary.html', rating_counts=rating_counts, service_counts=service_counts)


# --------------------------------------customer-------------------------------------


@app.route("/customer")
@login_required
@role_required("customer")
def customer_home():
    services = Service.query.all()
    Professional = aliased(User)
    service_history = db.session.query(ServiceRequest.id,
                                       Service.name,
                                       Professional.username.label(
                                           "professional_name"),
                                       ServiceRequest.task,
                                       ServiceRequest.service_status,
                                       ServiceRequest.time_of_request,
                                       ServiceRequest.time_of_completion
                                       ).join(Service, ServiceRequest.service_id == Service.id) \
        .join(Professional, ServiceRequest.professional_id == Professional.id) \
        .order_by(ServiceRequest.time_of_request.desc())
    service_history_data = service_history.all()
    return render_template("customers/c_home.html", services=services, service_history_data=service_history_data)


@app.route("/customer/<int:service_id>/select_professional")
@login_required
@role_required("customer")
def select_professional(service_id):
    professionals = User.query.filter(
        User.role == "professional", User.service_type == service_id, User.status == "verified").all()
    service = Service.query.get(service_id)
    avg_ratings = Review.query.with_entities(Review.professional_id, func.avg(
        Review.rating)).group_by(Review.professional_id).all()
    average_ratings_dict = dict()
    for result in avg_ratings:
        professional_id, avg_rating = result[0], result[1]
        average_ratings_dict[professional_id] = avg_rating
    return render_template("customers/c_select_professional.html", professionals=professionals, service=service, average_ratings_dict=average_ratings_dict)


@app.route("/book/<int:service_id>/<int:professional_id>", methods=["POST"])
@login_required
@role_required("customer")
def book_service(service_id, professional_id):
    form = BookServiceForm()
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
    if history_entry:
        history_entry.service_status = "closed"
        history_entry.time_of_completion = func.current_timestamp()
        db.session.commit()
        flash("Service closed successfully!", "success")
    else:
        flash("Service not found.", "error")
    return redirect(url_for("service_remarks", service_id=service_id))


@app.route("/remarks/<int:service_id>", methods=["GET", "POST"])
@login_required
@role_required("customer")
def service_remarks(service_id):
    history_entry = ServiceRequest.query.get_or_404(service_id)
    form = RemarksForm()
    form.service_id.data = history_entry.service_id
    form.professional_id.data = history_entry.professional_id
    if form.validate_on_submit():
        new_review = Review(
            service_request_id=history_entry.service_id,
            professional_id=history_entry.professional_id,
            customer_id=history_entry.customer_id,
            rating=form.rating.data,
            remarks=form.remarks.data
        )
        db.session.add(new_review)
        db.session.commit()
        flash("Remarks submitted successfully!", "success")
        return redirect(url_for("customer_home"))
    return render_template("customers/c_remarks.html", form=form, service_id=service_id)


@app.route('/customer/summary')
@login_required
@role_required("customer")
def customer_summary():
    ratings_data = Review.query.group_by(Review.rating).with_entities(
        Review.rating, db.func.count()).all()
    rating_counts = dict(ratings_data)
    service_requests = ServiceRequest.query.all()
    service_counts = {"Requested": 0,
                      "Accepted": 0, "Rejected": 0, "Closed": 0}
    for request in service_requests:
        if request.service_status == "requested":
            service_counts["Requested"] += 1
        elif request.service_status == "accepted":
            service_counts["Accepted"] += 1
        elif request.service_status == "rejected":
            service_counts["Rejected"] += 1
        elif request.service_status == "closed":
            service_counts["Closed"] += 1
    return render_template('customer/c_summary.html', rating_counts=rating_counts, service_counts=service_counts)


# -------------------------------professional-------------------------------


@app.route("/professional")
@login_required
@role_required("professional")
def professional_home():
    today_services = db.session.query(ServiceRequest.id,
                                      ServiceRequest.service_status,
                                      ServiceRequest.task,
                                      User.fullname.label("customer_fullname"),
                                      User.address.label("customer_address"),
                                      User.pincode.label("customer_pincode"),
                                      User.contact_number.label(
                                          "customer_contact_number")
                                      ).join(User, User.id == ServiceRequest.customer_id).filter(
        and_(ServiceRequest.professional_id == current_user.id,
             ServiceRequest.service_status == "requested")).all()
    ongoing_services = db.session.query(ServiceRequest.id,
                                        ServiceRequest.service_status,
                                        ServiceRequest.task,
                                        User.fullname.label(
                                            "customer_fullname"),
                                        User.address.label("customer_address"),
                                        User.pincode.label("customer_pincode"),
                                        User.contact_number.label(
                                            "customer_contact_number")
                                        ).join(User, User.id == ServiceRequest.customer_id).filter(
                                            and_(ServiceRequest.professional_id == current_user.id,
                                                 ServiceRequest.service_status == "accepted")).all()
    closed_services = db.session.query(ServiceRequest.id,
                                       ServiceRequest.service_status,
                                       ServiceRequest.task,
                                       User.fullname.label(
                                           "customer_fullname"),
                                       User.address.label("customer_address"),
                                       User.pincode.label("customer_pincode"),
                                       User.contact_number.label(
                                           "customer_contact_number")
                                       ).join(User, User.id == ServiceRequest.customer_id).filter(
                                           and_(or_(ServiceRequest.service_status == "rejected", ServiceRequest.service_status == "closed"),
                                                ServiceRequest.professional_id == current_user.id)).all()
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


@app.route('/professional/summary')
@login_required
@role_required("professional")
def professional_summary():
    ratings_data = Review.query.group_by(Review.rating).with_entities(
        Review.rating, db.func.count()).all()
    rating_counts = dict(ratings_data)
    service_requests = ServiceRequest.query.all()
    service_counts = {"Requested": 0,
                      "Accepted": 0, "Rejected": 0, "Closed": 0}
    for request in service_requests:
        if request.service_status == "requested":
            service_counts["Requested"] += 1
        elif request.service_status == "accepted":
            service_counts["Accepted"] += 1
        elif request.service_status == "rejected":
            service_counts["Rejected"] += 1
        elif request.service_status == "closed":
            service_counts["Closed"] += 1
    return render_template('professionals/p_summary.html', rating_counts=rating_counts, service_counts=service_counts)


if __name__ == "__main__":
    app.run()
