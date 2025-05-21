from flask import Flask, render_template, request, redirect, url_for, flash, session,abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import hashlib
from flask import jsonify
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from flask import send_from_directory
from werkzeug.utils import secure_filename
import os

# UPLOAD_FOLDER = '/uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}



app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Change this to a real secret key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'kesavansai1019@gmail.com'  # Replace with your Gmail
app.config['MAIL_PASSWORD'] = 'adlo wvqb hfiu wewe'     # Replace with your app password
app.config['MAIL_USE_TLS'] = True


UPLOAD_FOLDER = "/uploads"  # Adjust based on your actual upload folder
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    dob = db.Column(db.String(20), nullable=False)
    mobile = db.Column(db.String(15), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    graphical_password = db.Column(db.String(200), nullable=True)
    hash_password = db.Column(db.String(200), nullable=True)
    role = db.Column(db.String(10), nullable=True)
    login_failed_count = db.Column(db.Integer, default=0)  # New field for tracking failed logins
    status = db.Column(db.String(20), default='active')    # New field for account status
    
class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patient.id'), nullable=False)
    document_type = db.Column(db.String(50), nullable=False)  # e.g., 'text', 'image', 'description'
    file_path = db.Column(db.String(200), nullable=True)  # Path to the uploaded file
    description = db.Column(db.Text, nullable=True)  # Description of the document
    uploaded_at = db.Column(db.DateTime, default=db.func.current_timestamp())

    # Define a relationship to the Patient model
    patient = db.relationship('Patient', backref='documents')

class Patient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    patient_id = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    dob = db.Column(db.String(20), nullable=False)
    age = db.Column(db.Integer, nullable=False)
    email = db.Column(db.String(100), nullable=False)
    blood_group = db.Column(db.String(5), nullable=False)  # Blood group field
    gender = db.Column(db.String(10), nullable=False) 
    nominee_name = db.Column(db.String(100), nullable=False)
    nominee_relationship = db.Column(db.String(50), nullable=False)
    nominee_mobile = db.Column(db.String(15), nullable=False)
    nominee_email = db.Column(db.String(100), nullable=False)

    # Define a relationship to the User model
    user = db.relationship('User', backref='patients')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/uploads/<filename>")
def serve_file(filename):
    try:
        return send_from_directory(app.config["UPLOAD_FOLDER"], filename)
    except FileNotFoundError:
        abort(404)

@app.route('/static/uploads/<filename>')
def download_file(filename):
    # Prevent directory traversal
    if '..' in filename or filename.startswith('/') or filename.startswith('\\'):
        abort(403)
    
    # Serve the file from the 'static/uploads' directory
    file_path = os.path.join('static', 'uploads', filename)
    if not os.path.isfile(file_path):
        abort(404)  # File not found
    
    return send_from_directory(os.path.join('static', 'uploads'), filename, as_attachment=True)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/admin')
def admin():
    return render_template('admindash.html')
def send_email(subject, body, to_email):
    try:
        msg = MIMEMultipart()
        msg['From'] = app.config['MAIL_USERNAME']
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
        server.starttls()
        server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False
    
    
    
# Auto-generate Patient ID function
def generate_patient_id():
    last_patient = Patient.query.order_by(Patient.id.desc()).first()
    if last_patient:
        last_id = int(last_patient.patient_id[2:])  # Extract number part
        new_id = f"PT{last_id + 1:03d}"  # Increment and format (e.g., PT002)
    else:
        new_id = "PT001"  # First patient
    return new_id

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        dob = request.form.get('dob')
        mobile = request.form.get('mobile')
        email = request.form.get('email')
        password = request.form.get('password')
        
        role = "User"

        if not all([name, dob, mobile, email, password]):
            flash("All fields are required!", "danger")
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash("Email already registered!", "danger")
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(password)
        new_user = User(
            name=name,
            dob=dob,
            mobile=mobile,
            email=email,
            password=password,
            hash_password=hashed_password, # Storing as plain text
            role=role
        )
        try:
            db.session.add(new_user)
            session['email'] = new_user.email  # ✅ Correct

            db.session.commit()
            session['user_id'] = new_user.id  # Store user_id instead of email
            flash("Registration successful! Proceed to graphical registration.", "success")
            return redirect(url_for('graphical_register'))
        except Exception as e:
            db.session.rollback()
            flash(f"Error storing data: {str(e)}", "danger")
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/graphical_register', methods=['GET', 'POST'])
def graphical_register():
    username = request.form.get('username') 
    if 'user_id' not in session:
        flash("Please complete step 1 first.", "danger")
        return redirect(url_for('register'))

    user = User.query.get(session['user_id'])
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('register'))

    if request.method == 'POST':
        session["username"]= username
        selected_images = request.form.getlist('selected_images')
        if len(selected_images) < 3:
            flash("Select at least 3 images.", "warning")
            return redirect(url_for('graphical_register'))

        try:
            user.graphical_password = ','.join(selected_images)
            db.session.commit()
            flash("Graphical registration complete! Proceed to patient registration.", "success")
            return redirect(url_for('patient_register'))
        except Exception as e:
            db.session.rollback()
            flash(f"Error storing graphical password: {str(e)}", "danger")
            return redirect(url_for('graphical_register'))

    return render_template('graphical_register.html')


@app.route('/patient_register', methods=['GET', 'POST'])
def patient_register():
    patient_id = generate_patient_id()
    if 'user_id' not in session:
        flash("Please complete step 1 first.", "danger")
        return redirect(url_for('register'))

    user = User.query.get(session['user_id'])
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for('register'))

    if request.method == 'POST':
        patient_id = patient_id
        name = request.form.get('name')
        dob = request.form.get('dob')
        age = request.form.get('age')
        email = request.form.get('email')
        nominee_name = request.form.get('nominee_name')
        nominee_relationship = request.form.get('nominee_relationship')
        nominee_mobile = request.form.get('nominee_mobile')
        nominee_email = request.form.get('nominee_email')
        gender = request.form.get('gender')
        blood_group = request.form.get('blood_group')

        if not all([patient_id, name, dob, age, email, nominee_name, nominee_relationship, nominee_mobile, nominee_email, gender, blood_group]):
            flash("All fields are required!", "danger")
            return redirect(url_for('patient_register'))

        new_patient = Patient(
            user_id=user.id,
            patient_id=patient_id,
            name=name,
            dob=dob,
            age=int(age),
            email=email,
            nominee_name=nominee_name,
            nominee_relationship=nominee_relationship,
            nominee_mobile=nominee_mobile,
            nominee_email=nominee_email,
            blood_group=blood_group,
            gender=gender
        )

        try:
            db.session.add(new_patient)
            db.session.commit()

            # Set session flag to indicate registration is complete
            session['registration_complete'] = True

            # Fetch stored hashed password
            hashed_password = user.hash_password

            # Send email to user with hashed password
            user_subject = "Your Registration Details"
            user_body = f"""
            Hello {user.name},

            Your registration has been completed successfully!
            Your login email: {user.email}
            Your hashed password: {hashed_password} (Do not share this)

            Please keep this information safe.

            Thank you for registering!
            """
            user_email_sent = send_email(user_subject, user_body, user.email)

            # Send email to nominee
            nominee_subject = "Nominee Registration Notification"
            nominee_body = f"""
            Hello {nominee_name},

            This email is to inform you that you have been registered as a nominee for {user.name}.

            Patient Details:
            Name: {name}
            Patient ID: {patient_id}
            Patient login email: {user.email}
            Patient hashed password: {hashed_password} (Do not share this)
            Documents successfully shared to patients and you can accessed it. 
            Thank you!
            """
            nominee_email_sent = send_email(nominee_subject, nominee_body, nominee_email)

            if not user_email_sent or not nominee_email_sent:
                flash("Registration successful but there was an error sending emails. Please contact support.", "warning")
            else:
                flash("Registration successful! Confirmation emails have been sent.", "success")

            session.pop('user_id', None)  # Clear the session
            return redirect(url_for('home'))

        except Exception as e:
            db.session.rollback()
            flash(f"Error storing data: {str(e)}", "danger")
            return redirect(url_for('patient_register'))

    return render_template('patient_register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user and user.status == 'locked':
            flash("Your account is locked. Please contact admin for unlocking.", "danger")
            return redirect(url_for('home'))

        # Directly compare input password with the stored hash_password column
        if user and user.hash_password == password: 
            session["email"] = email 
            # Reset failed login count on successful login
            user.login_failed_count = 0
            db.session.commit()
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for('upload_document'))
        else:
            if user:
                user.login_failed_count += 1
                if user.login_failed_count >= 3:
                    user.status = 'locked'
                    flash("Account locked due to multiple failed attempts. Contact admin.", "danger")
                else:
                    flash(f"Invalid credentials. {3 - user.login_failed_count} attempts remaining.", "danger")
                db.session.commit()
            else:
                flash("Invalid credentials.", "danger")

    return render_template('login.html')


@app.route('/patient_login', methods=['GET', 'POST'])
def patient_login():
    if request.method == 'POST':
        username = request.form.get('username')  # Username is the email
        password = request.form.get('password')  # Plain text password

        user = User.query.filter_by(email=username).first()

        if user and user.status == 'locked':
            return jsonify({'status': 'error', 'message': "Your account is locked. Please contact admin for unlocking."})

        if user and user.password == password:
            # Reset failed login count on successful login
            user.login_failed_count = 0
            db.session.commit()
            login_user(user)  # Login the user
            session["username"] = username  # Store email in session

            # Redirect based on role
            if user.role == "Admin":
                return jsonify({'status': 'success', 'message': "Login successful!", 'redirect': url_for('admin')})
            else:
                return jsonify({'status': 'success', 'message': "Login successful!", 'redirect': url_for('graphical_login')})

        else:
            if user:
                user.login_failed_count += 1
                if user.login_failed_count >= 3:
                    user.status = 'locked'
                    db.session.commit()
                    return jsonify({'status': 'error', 'message': "Account locked due to multiple failed attempts. Contact admin."})
                else:
                    db.session.commit()
                    return jsonify({'status': 'error', 'message': f"Invalid credentials. {3 - user.login_failed_count} attempts remaining."})
            else:
                return jsonify({'status': 'error', 'message': "Invalid credentials. Please try again."})

    return render_template('patient_login.html')



@app.route('/graphical_login', methods=['GET', 'POST'])
def graphical_login():
    if request.method == 'POST':
        email = request.form.get('email')
        selected_images = request.form.getlist('selected_images')  # List of selected images

        user = User.query.filter_by(email=email).first()
        
        if user and user.status == 'locked':
            return jsonify({
                'status': 'error',
                'message': "Your account is locked. Please contact admin for unlocking."
            })
            
        if user:
            stored_graphical_password = user.graphical_password.split(',')  # Convert stored password to list
            selected_images.sort()  # Ensure order consistency
            stored_graphical_password.sort()  # Ensure stored order matches
            
            if selected_images == stored_graphical_password:
                # Reset failed login count on successful login
                user.login_failed_count = 0
                db.session.commit()
                login_user(user)
                return jsonify({
                    'status': 'success',
                    'message': "Graphical Login successful!",
                    'redirect': url_for('login')  # Redirect to the dashboard or desired route
                })
            else:
                user.login_failed_count += 1
                if user.login_failed_count >= 3:
                    user.status = 'locked'
                    db.session.commit()
                    return jsonify({
                        'status': 'error',
                        'message': "Account locked due to multiple failed attempts. Contact admin."
                    })
                else:
                    db.session.commit()
                    return jsonify({
                        'status': 'error',
                        'message': f"Graphical authentication failed. {3 - user.login_failed_count} attempts remaining."
                    })
        else:
            return jsonify({
                'status': 'error',
                'message': "User not found."
            })

    return render_template('graphical_login.html')


@app.route('/admin/locked_accounts')
@login_required
def locked_accounts():
    if current_user.role != 'Admin':
        flash("Unauthorized access", "danger")
        return redirect(url_for('home'))
        
    locked_users = User.query.filter(User.login_failed_count >= 3).all()
    return render_template('locked_accounts.html', users=locked_users)


@app.route('/admin/unlock_account/<int:user_id>', methods=['POST'])
@login_required
def unlock_account(user_id):
    if current_user.role != 'Admin':
        flash("Unauthorized access", "danger")
        return redirect(url_for('home'))
        
    user = User.query.get_or_404(user_id)
    user.status = 'active'
    user.login_failed_count = 0
    db.session.commit()
    
    # Send email notification to user
    subject = "Your Account Has Been Unlocked"
    body = f"""
    Hello {user.name},
    
    Your account has been unlocked by the administrator. You can now log in to your account.
    
    If you have any questions, please contact support.
    
    Thank you,
    MediSync Team
    """
    send_email(subject, body, user.email)
    
    flash(f"Account for {user.email} has been unlocked successfully.", "success")
    return redirect(url_for('locked_accounts'))


@app.route('/request_demo', methods=['POST'])
def request_demo():
    user_email = request.form.get('user_email')
    subject = request.form.get('subject')

    if not user_email:
        flash("Please provide your email address.", "danger")
        return redirect(url_for('home'))

    admin_email = "22bct044@psgcas.ac.in"  # Admin email

    # Email content for the admin
    admin_subject = subject
    admin_body = f"""
    A new account unlock request has been received.

    Email: {user_email}

    Please follow up with this user.
    """
    send_email(admin_subject, admin_body, admin_email)

    # Email content for the user
    user_subject = "Request for Unlocking Account"
    user_body = f"""
    Hello,

    Thank you for reaching out!

    We have received your request, and our team will unlock your account as soon as possible.

    Best regards,  
    MediSync Team
    """
    send_email(user_subject, user_body, user_email)

    flash("Your unlock request has been submitted. We'll contact you shortly!", "success")
    return redirect(url_for('home'))



@app.route('/dashboard')
@login_required
def dashboard():
 return render_template('dashboard.html')

@app.route('/logout')
@login_required
def logout():
    session.pop('registration_complete', None)  # Clear the registration flag
    logout_user()
    flash("Logged out successfully.", "info")
    return redirect(url_for('home'))

from flask import flash, redirect, url_for

@app.route('/upload_document', methods=['GET', 'POST'])
@login_required
def upload_document():
    if request.method == 'POST':
        # Fetch the patient record for the current user
        patient = Patient.query.filter_by(user_id=current_user.id).first()
        
        if not patient:
            flash("No patient record found for the current user.", "danger")
            return redirect(url_for('upload_document'))

        patient_id = patient.id  # Use the patient's ID, not the user's ID
        document_type = request.form.get('document_type')
        description = request.form.get('description')
        file = request.files.get('file')

        if not document_type:
            flash("Document type is required.", "danger")
            return redirect(url_for('upload_document'))

        # Save the file if it exists
        file_path = None
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

        # Save the document to the database
        new_document = Document(
            patient_id=patient_id,  # Use the patient's ID
            document_type=document_type,
            file_path=file_path,
            description=description
        )
        db.session.add(new_document)
        db.session.commit()

        flash("Document uploaded successfully!", "success")
        return redirect(url_for('upload_document'))  # Redirect back to the upload page

    return render_template('upload_document.html')


@app.route('/download/<filename>')
def save_file(uploaded_file):
    filename = secure_filename(uploaded_file.filename)  # Ensure safe filenames
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    uploaded_file.save(file_path)
  
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=True)


# Add this debugging code to your route
@app.route('/document_management')
@login_required
def document_management():
    # Fetch the patient record for the current user
    patient = Patient.query.filter_by(user_id=current_user.id).first()
    
    if not patient:
        flash("No patient record found for the current user.", "danger")
        return redirect(url_for('home'))

    # Fetch documents for the patient
    documents = Document.query.filter_by(patient_id=patient.id).all()
    
    if not documents:
        flash("No documents found. Please upload some documents.", "info")
    
    return render_template('document_management.html', documents=documents)


@app.route('/Patient_details')
def Patient_details():
    username = session.get("email")

    user = Patient.query.filter_by(email=username).first()
    print("Current User", username)
    if not Patient:
        flash("No patient details found for this user.", "warning")
        return redirect(url_for('home'))

    return render_template('patient_details.html', patient=user)



@app.route('/edit_document/<int:document_id>', methods=['POST'])
@login_required
def edit_document(document_id):
    try:
        document = Document.query.get_or_404(document_id)
        
        # Verify ownership
        patient = Patient.query.filter_by(user_id=current_user.id).first()
        if not patient or document.patient_id != patient.id:
            return jsonify({'success': False, 'error': 'Unauthorized access'}), 403

        # Update description
        description = request.form.get('description')
        if description:
            document.description = description

        # Handle file upload if new file is provided
        if 'file' in request.files:
            file = request.files['file']
            if file and file.filename:
                filename = secure_filename(file.filename)
                # Create unique filename
                unique_filename = f"{document_id}_{filename}"
                
                # Define upload path (make sure this directory exists)
                upload_dir = os.path.join(app.static_folder, 'uploads')
                if not os.path.exists(upload_dir):
                    os.makedirs(upload_dir)
                
                # Save file
                file_path = os.path.join(upload_dir, unique_filename)
                file.save(file_path)
                
                # Update database with new file path
                document.file_path = f'uploads/{unique_filename}'

        db.session.commit()
        return jsonify({'success': True})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})



# Fetch all patients
@app.route('/patients')
def list_patients():
    patients = Patient.query.all()  # Get all patients from DB
    return render_template('patients.html', patients=patients)  # Render patient list page


# Fetch specific patient and their documents


@app.route('/patient_records')
def patient_records():
    patients = Patient.query.all()  # Fetch all patients from the database
    return render_template('patientrec.html', patients=patients)  # Render the patient list page

@app.route('/patient/<int:patient_id>')
def view_patient(patient_id):
    print(f"🔍 Received Patient ID: {patient_id}")  # Debugging
    
    # Fetch patient from database
    patient = Patient.query.get(patient_id)
    
    if not patient:
        print("❌ Patient Not Found!")
        return "Patient Not Found", 404
    
    # Fetch patient documents
    documents = Document.query.filter_by(patient_id=patient_id).all()
    print(f"📂 Documents Found: {len(documents)}")  # Debugging
    
    # Pass both patient and documents to template
    return render_template('view.html', patient=patient, documents=documents)

@app.route('/delete_document/<int:document_id>', methods=['DELETE'])
@login_required
def delete_document(document_id):
    try:
        document = Document.query.get_or_404(document_id)
        
        # Verify ownership
        patient = Patient.query.filter_by(user_id=current_user.id).first()
        if not patient or document.patient_id != patient.id:
            return jsonify({'success': False, 'error': 'Unauthorized access'}), 403

        # Delete the file if it exists
        if document.file_path:
            file_path = os.path.join(app.static_folder, document.file_path)
            if os.path.exists(file_path):
                os.remove(file_path)

        db.session.delete(document)
        db.session.commit()
        
        return jsonify({'success': True})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})


@app.route('/dash') 
def dash(): 
    total_patients = Patient.query.count()  # Fetch patient count from DB
     # Fetch nominee count from DB
    return render_template('dash.html', total_patients=total_patients)
@app.route('/view') 
def view(): 
    return render_template('view.html')

@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    user_email = request.form.get('user_email')
    patient_id = request.form.get('patient_id')
    feedback = request.form.get('feedback')
    rating = request.form.get('rating')

    if not user_email or not patient_id or not feedback or not rating:
        flash("All fields are required.", "danger")
        return redirect(url_for('home'))

    # Email content for the admin
    admin_subject = "New Feedback Submitted"
    admin_body = f"""
    A new feedback has been received.

    Email: {user_email}
    Patient ID: {patient_id}
    Feedback: {feedback}
    Rating: {rating} stars

    Please review the feedback and follow up accordingly.
    """
    send_email(admin_subject, admin_body, "pandisudha2006@gmail.com")  # Admin email

    # Email content for the user (confirmation)
    user_subject = "Feedback Received"
    user_body = f"""
    Hello,

    Thank you for your feedback!

    We appreciate your input and will use it to improve our services.

    Best regards,  
    MediSync Team
    """
    send_email(user_subject, user_body, user_email)

    flash("Your feedback has been submitted. Thank you for sharing your thoughts!", "success")
    return redirect(url_for('home'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create new tables with updated schema
        print("Database tables created successfully!")

app.run(debug=True)
