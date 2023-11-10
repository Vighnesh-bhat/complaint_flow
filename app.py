from flask import Flask, render_template, request, redirect, url_for,flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin,current_user,login_user,logout_user, login_required
from sqlalchemy.exc import IntegrityError
from sqlalchemy import desc  # Import desc for sorting by date in descending order
from config import DATABASE_PASSWORD
from werkzeug.security import check_password_hash, generate_password_hash
from flask import make_response
import re
app = Flask(__name__)
app.secret_key = 'xyzsdfg'

app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:@localhost/user-system'
db = SQLAlchemy(app)

class User(db.Model, UserMixin):
    userid = db.Column(db.String(10), primary_key=True)
    name = db.Column(db.String(100), unique=False, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), unique=False, nullable=False)
    roomno = db.Column(db.Integer, unique=False, nullable=False)
    def get_id(self):
        return self.userid


# Assuming you already have the 'app' and 'db' objects created

class Complaints(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.String(10), db.ForeignKey('user.userid'), nullable=False)
    category = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=False)
    submission_date = db.Column(db.TIMESTAMP, server_default=db.func.current_timestamp(), nullable=False)
    room_number = db.Column(db.Integer, nullable=False)
    email_id = db.Column(db.String(100), nullable=False)
    feedback = db.Column(db.Text,server_default=None)
    status = db.Column(db.Enum('Pending', 'In Progress', 'Resolved'), nullable=False)

    # Define a relationship to the User model
    user = db.relationship('User', backref='complaints')

    def __init__(self, user_id, category, description, room_number, email_id):
        self.user_id = user_id
        self.category = category
        self.description = description
        self.room_number = room_number
        self.email_id = email_id
        self.status = 'Pending'  # Default status
        self.feedback = None
    
    def get_id(self):
        return self.id

    # Add any additional methods or properties as needed
class Admin(db.Model,UserMixin):
    admin_id = db.Column(db.String(10), primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    def get_id(self):
        return self.admin_id
    def get_password(self):
        return self.password


login_manager = LoginManager()
login_manager.login_view = "user_login"  # For user login
login_manager.login_view = "admin_login"  # For admin login 
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    # Check if the user_id exists in the User model
    user = User.query.get(user_id)
    if user:
        return user

    # Check if the user_id exists in the Admin model
    admin = Admin.query.get(user_id)
    if admin:
        return admin

    # If neither User nor Admin found, return None (user not authenticated)
    return None
    

@app.route('/')
def landing():
    # Your landing page logic here
    response = make_response(render_template('landing.html'))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

    return render_template('landing.html')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if current_user.is_authenticated:
        return redirect(url_for("admin_dashboard"))
    
    if request.method == 'POST':
        admin_id = request.form.get('admin_id')
        password = request.form.get('password')
        
        admin = Admin.query.filter_by(admin_id=admin_id).first()
        
        if admin is not None and admin.password == password:
            # Use the login_user method to log in the admin
            login_user(admin)
            return redirect(url_for('admin_dashboard'))
        else:
            flash("Login failed. Please check your credentials.", "danger")
    
    return render_template('admin_login.html')

@app.route('/admin_register_check', methods=['GET', 'POST'])
def admin_register_check():
    if request.method == 'POST':
        entered_password = request.form.get('entered_password')
        
        # Replace 'your_secret_password' with the actual secret password
        if entered_password ==DATABASE_PASSWORD :
            return redirect(url_for('admin_register'))

    return render_template('admin_register_password.html')

@app.route('/admin_register', methods=['GET', 'POST'])
def admin_register():
    if request.method == 'POST':
        admin_id = request.form.get('admin_id')
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')

        admin = Admin(admin_id=admin_id, name=name, email=email, password=password)
        db.session.add(admin)
        db.session.commit()
        return redirect(url_for('admin_login'))
    return render_template('admin_register.html')  



@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    # Fetch all pending complaints and sort them by date of submission (newest first)
    pending_complaints = Complaints.query.filter_by(status='Pending').order_by(desc(Complaints.submission_date)).all()

    return render_template('admin_dashboard.html', pending_complaints=pending_complaints)


@app.route('/admin_profile')
@login_required
def admin_profile():
    # Assuming you have an 'Admin' model for your admin profiles
    admin = Admin.query.get(current_user.admin_id)  # Replace 'Admin' with your actual Admin model
    
    if admin:
        return render_template('admin_profile.html', admin=admin)
    else:
        flash("Admin profile not found.", "danger")
        return redirect(url_for('admin_dashboard'))
    
@app.route('/edit_admin_profile', methods=['GET', 'POST'])
@login_required
def edit_admin_profile():
    if not current_user.is_authenticated:
        flash("You don't have permission to edit the admin profile.", "danger")
        return redirect(url_for('admin_dashboard'))

    # Fetch the admin data from the database using the current user's ID
    admin = Admin.query.get(current_user.admin_id)
    if request.method == 'POST':
        # Get the edited profile information from the form
        new_name = request.form.get('name')
        new_email = request.form.get('email')

        # Update the admin's profile information
        admin = Admin.query.get(current_user.admin_id)
        if admin:
            admin.name = new_name
            admin.email = new_email

            # Commit the changes to the database
            db.session.commit()

            flash("Profile updated successfully.", "success")
        else:
            flash("Admin profile not found.", "danger")

    return render_template('edit_admin_profile.html', admin=admin)

@app.route('/change_admin_password', methods=['GET', 'POST'])
@login_required
def change_admin_password():
    # Check if the user is logged in as an admin
    if not current_user.is_authenticated:
        flash("You don't have permission to change the admin password.", "danger")
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # Fetch the admin data from the database using the current user's ID
        admin = Admin.query.get(current_user.admin_id)

        # Verify the old password
        if admin.password != old_password:
            flash("Old password is incorrect. Password not changed.", "danger")
            return redirect(url_for('change_admin_password'))

        # Check if the new password and confirmation match
        if new_password != confirm_password:
            flash("New password and confirmation do not match. Password not changed.", "danger")
            return redirect(url_for('change_admin_password'))

        # Hash and update the new password
        admin.password = new_password

        # Commit the changes to the database
        db.session.commit()

        flash("Admin password changed successfully.", "success")
        return redirect(url_for('admin_dashboard'))

    return render_template('edit_admin_password.html')


@app.route('/admin_monitor_users')
@login_required  # Add authentication as needed
def admin_monitor_users():
    # Retrieve all users from the database
    users = User.query.all()

    return render_template('admin_monitor_users.html', users=users)

# Define the route to view user complaints
@app.route('/view_user_complaints/<user_id>')
@login_required  # Add authentication as needed
def view_user_complaints(user_id):
    # Retrieve the user's complaints from the database
    user = User.query.get(user_id)
    
    if user is None:
        flash("User not found.", "danger")
        return redirect(url_for('admin_monitor_users'))

    # Assuming you have a relationship set up in your models, get the complaints
    complaints = user.complaints  # This should be a list of complaints associated with the user
    return render_template('view_user_complaints.html', user=user, complaints=complaints)


@app.route('/admin_complaints_history',methods=['GET'])
@login_required
def admin_complaints_history():
    # Fetch all complaints and sort them by the date of submission (newest first)
    all_complaints = Complaints.query.order_by(Complaints.submission_date.desc()).all()
    return render_template('admin_complaints_history.html',all_complaints=all_complaints)


@app.route('/view_complaint/<int:complaint_id>')
@login_required
def view_complaint(complaint_id):
    # Retrieve the complaint with the given ID from the database
    complaint = Complaints.query.get(complaint_id)
    return render_template('complaint_details.html', complaint=complaint)




@app.route('/admin/resolve_complaint/<int:complaint_id>', methods=['GET'])
@login_required
def resolve_complaint(complaint_id):
    complaint = Complaints.query.get(complaint_id)
    
    if complaint:
        # Change the status to "Resolved" or another appropriate status
        complaint.status = 'Resolved'
        db.session.commit()
        flash("Complaint marked as resolved successfully.", "success")
    else:
        flash("Complaint not found.", "danger")
    
    return redirect(url_for('admin_dashboard'))


@app.route('/user_dashboard', methods=['GET', 'POST'])
@login_required
def user_dashboard():
    if request.method == 'POST':
        # Get the complaint details from the form
        complaint_category = request.form.get('complaint_category')
        complaint_description = request.form.get('complaint_description')
        
        # Create a new complaint object
        new_complaint = Complaints(
            user_id=current_user.userid,
            category=complaint_category,
            description=complaint_description,
            room_number=current_user.roomno,
            email_id=current_user.email
        )
        
        # Add the complaint to the database
        db.session.add(new_complaint)
        db.session.commit()
        
        flash("Complaint submitted successfully.", "success")

    return render_template('user_dashboard.html')


@app.route('/user_profile')
@login_required
def user_profile():
    # Assuming you have an 'Admin' model for your admin profiles
    user = User.query.get(current_user.userid)  # Replace 'Admin' with your actual Admin model
    
    if user:
        return render_template('user_profile.html', user=user)
    else:
        flash("User profile not found.", "danger")
        return redirect(url_for('user_dashboard'))
    

@app.route('/edit_user_profile', methods=['GET', 'POST'])
@login_required
def edit_user_profile():
    if not current_user.is_authenticated:
        flash("You don't have permission to edit the user profile.", "danger")
        return redirect(url_for('user_dashboard'))

    # Fetch the admin data from the database using the current user's ID
    user = User.query.get(current_user.userid)
    if request.method == 'POST':
        # Get the edited profile information from the form
        new_name = request.form.get('name')
        new_email = request.form.get('email')
        new_roomno= request.form.get('roomno')

        # Update the admin's profile information
        user = User.query.get(current_user.userid)
        if user:
            user.name = new_name
            user.email = new_email
            user.roomno=new_roomno

            # Commit the changes to the database
            db.session.commit()

            flash("Profile updated successfully.", "success")
        else:
            flash("User profile not found.", "danger")

    return render_template('edit_user_profile.html', user=user)

@app.route('/edit_user_password', methods=['GET', 'POST'])
@login_required
def edit_user_password():
    # Check if the user is logged in as an admin
    if not current_user.is_authenticated:
        flash("You don't have permission to change the user password.", "danger")
        return redirect(url_for('user_dashboard'))

    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # Fetch the admin data from the database using the current user's ID
        user = User.query.get(current_user.userid)

        # Verify the old password
        if user.password != old_password:
            flash("Old password is incorrect. Password not changed.", "danger")
            return redirect(url_for('edit_user_password'))

        # Check if the new password and confirmation match
        if new_password != confirm_password:
            flash("New password and confirmation do not match. Password not changed.", "danger")
            return redirect(url_for('edit_user_password'))

        # Hash and update the new password
        user.password = new_password

        # Commit the changes to the database
        db.session.commit()

        flash("User password changed successfully.", "success")
        return redirect(url_for('user_dashboard'))

    return render_template('edit_user_password.html')
    

@app.route('/user_login', methods=['GET', 'POST'])
def user_login():
    # If a post request was made, find the user by
    # filtering for the username
     # Check if the user is already authenticated (logged in)
    if current_user.is_authenticated:
        flash("You are already logged in.", "info")
        return redirect(url_for("user_dashboard"))  # Redirect to user_dashboard if logged in
    if request.method == "POST":
        userid = request.form.get("userid")
        password = request.form.get("password")
        
        user = User.query.filter_by(userid=userid).first()
        
        if user is not None and user.password == password:
            # Use the login_user method to log in the user
            login_user(user)
            return redirect(url_for("user_dashboard"))
        else:
            flash("Login failed. Please check your credentials.","danger")
    
    return render_template("user_login.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Retrieve form inputs
        userid = request.form.get('userid')
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        roomno = request.form.get('room_number')

        # Check if the user ID follows the format '4NI21CS120'
        if not re.match(r'^4NI\d{2}[A-Za-z]{2}\d{3}$', userid):
            flash("User ID should follow the format '4NI21CS120'.", "danger")
        # Check if the email ends with '@gmail.com'
        elif not email.lower().endswith('@gmail.com'):
            flash("Email should end with '@gmail.com'.", "danger")
        # Check if the room number is three digits
        elif not re.match(r'^\d{3}$', roomno):
            flash("Room number should be three digits.", "danger")
        else:
            # If all checks pass, create the user entry
            entry = User(userid=userid, name=name, email=email, password=password, roomno=roomno)
            try:
                db.session.add(entry)
                db.session.commit()
                return redirect(url_for('user_login'))
            except IntegrityError:
                db.session.rollback()
                flash("User ID already exists. Please choose a different User ID.", "danger")

    return render_template('register.html')



@app.route('/complaints')
@login_required
def complaints():
    # Fetch the user's complaints here and pass them to the template
    user_complaints = Complaints.query.filter_by(user_id=current_user.userid).all()
    return render_template('complaints.html', user_complaints=user_complaints)

@app.route('/provide_feedback/<int:complaint_id>', methods=['GET', 'POST'])
@login_required
def provide_feedback(complaint_id):
    # Check if the complaint with the given ID exists and belongs to the current user
    complaint = Complaints.query.filter_by(id=complaint_id, user_id=current_user.userid).first()

    if not complaint:
        flash("Complaint not found or doesn't belong to you.", "danger")
        return redirect(url_for('user_dashboard'))

    if request.method == 'POST':
        feedback = request.form.get('feedback')

        # Update the feedback for the complaint
        complaint.feedback = feedback

        # Update the status to 'Resolved' (or as appropriate) if needed
        #complaint.status = 'Resolved'

        # Commit the changes to the database
        db.session.commit()

        flash("Feedback submitted successfully.", "success")
        return redirect(url_for('user_dashboard'))

    return render_template('feedback_submission.html', complaint=complaint)



@app.route('/user_logout')
@login_required
def user_logout():
    logout_user()
    db.session.remove()  # Clear the session data
    return redirect(url_for('landing'))  # Redirect to the landing page or another page

@app.route('/admin_logout')
def admin_logout():
    logout_user()
    db.session.remove()  # Clear the session data
    return redirect(url_for('landing'))

if __name__ == "__main__":
    app.run(debug=True)
