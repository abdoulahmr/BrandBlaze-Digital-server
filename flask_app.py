from datetime import datetime
from flask import Flask, jsonify, request
from models import InstagramMarketingRequest, Messages, RequestIDs, SnapchatMarketingRequest, TiktokMarketingRequest, db, User, FacebookMarketingRequest
from config import Config
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager, unset_jwt_cookies
from sqlalchemy.exc import SQLAlchemyError

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)
limiter = Limiter(get_remote_address, app=app)
jwt = JWTManager(app)

with app.app_context():
    db.create_all()

# API route for routes
@app.route('/api/', methods=['GET'])
def routes():
    available_routes = {
        'login': '/api/login',
        'register': '/api/register',
        'logout': '/api/logout',
        'protected': '/api/protected',
        'user': '/api/user'
    }
    return jsonify(available_routes), 200

# API route to register a new user
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()

    if not all(k in data for k in ('username', 'email', 'password')):
        return jsonify({'error': 'Missing required fields'}), 400

    hashed_password = generate_password_hash(data['password'])

    new_user = User(username=data['username'], email=data['email'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message":"Register done"}), 201

# API route to login a user
@app.route('/api/login', methods=['POST'])
@limiter.limit("5 per minute")
def login():
    data = request.get_json()

    if not all(k in data for k in ('password',)):
        return jsonify({'error': 'Missing password'}), 400

    user = None
    if 'username' in data:
        user = User.query.filter_by(username=data['username']).first()
    elif 'email' in data:
        user = User.query.filter_by(email=data['email']).first()

    if user and check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity=user.username)
        return jsonify(access_token=access_token), 200

    return jsonify({'error': 'Invalid credentials'}), 401

# API route for logout
@app.route('/api/logout', methods=['DELETE'])
@jwt_required()
def logout():
    # Unset the JWT cookies to log out the user
    response = jsonify({"msg": "Logout successful"})
    unset_jwt_cookies(response)
    return response, 200

# API Protected route, requires a valid JWT token to access
@app.route('/api/protected', methods=['GET'])
@jwt_required()
def protected():
    return jsonify({'message': 'You have access to this protected route'}), 200

# API route to get user information
@app.route('/api/user', methods=['GET'])
@jwt_required()
def user():
    current_identity = get_jwt_identity()
    current_user = User.query.filter_by(username=current_identity).first()

    if current_user:
        return jsonify(current_user.to_dict()), 200
    else:
        return jsonify({'error': 'User not found'}), 404

# API route to submit a sponsor request
@app.route('/api/submit_sponsor_request/<int:id>', methods=['POST'])
def submit_sponsor_request(id):
    data = request.get_json()

    page_name = data.get('page_name')
    page_url = data.get('page_url')
    campaign_objective = data.get('campaign_objective')
    target_audience = data.get('target_audience')
    budget = data.get('budget')
    duration = data.get('duration')
    user_id = data.get('user_id')

    if not page_name or not page_url or not campaign_objective or not budget or not duration or not user_id:
        return jsonify({'error': 'Page name, URL, campaign objective, budget, duration, and user ID are required!'}), 400

    # Handle different request types using if-elif
    if id == 1:
        new_request = FacebookMarketingRequest(
            page_name=page_name,
            page_url=page_url,
            campaign_objective=campaign_objective,
            target_audience=target_audience,
            budget=budget,
            duration=duration,
        )
    elif id == 2:
        new_request = InstagramMarketingRequest(
            page_name=page_name,
            page_url=page_url,
            campaign_objective=campaign_objective,
            target_audience=target_audience,
            budget=budget,
            duration=duration,
        )
    elif id == 3:
        new_request = SnapchatMarketingRequest(
            page_name=page_name,
            page_url=page_url,
            campaign_objective=campaign_objective,
            target_audience=target_audience,
            budget=budget,
            duration=duration,
        )
    elif id == 4:
        new_request = TiktokMarketingRequest(
            page_name=page_name,
            page_url=page_url,
            campaign_objective=campaign_objective,
            target_audience=target_audience,
            budget=budget,
            duration=duration,
        )
    else:
        return jsonify({'error': 'Invalid marketing request type!'}), 400

    try:
       # Start a transaction
        db.session.add(new_request)
        db.session.commit()  # Commit to get the new_request.id

        # Create an entry for request_id
        new_request_id = RequestIDs(
            user_id=user_id,
            request_type=id,
        )

        db.session.add(new_request_id)
        db.session.commit()  # Commit to get the new_request_id.id

        # Create a message for the user
        new_message = Messages(
            message=f"New marketing request submitted:\n"
                    f"Platform: {'Facebook' if id == 1 else 'Instagram' if id == 2 else 'Snapchat' if id == 3 else 'TikTok'}\n"
                    f"Page Name: {page_name}\n"
                    f"Page URL: {page_url}\n"
                    f"Objective: {campaign_objective}\n"
                    f"Target Audience: {target_audience}\n"
                    f"Budget: ${budget}\n"
                    f"Duration: {duration} days",
            user_id=user_id,
            request_id=new_request_id.id,  # Use the ID of the newly created request_id
        )

        db.session.add(new_message)
        db.session.commit()

    except SQLAlchemyError as e:
        # Roll back all changes if there's an error
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

    return jsonify({'message': 'Marketing request submitted successfully!'}), 200

# API route to get requests by user ID
@app.route('/api/get_requests/<int:id>', methods=['GET'])
def get_requests(id):
    requests = RequestIDs.query.filter_by(user_id=id).all()
    if not requests:
        return jsonify({'error': 'No requests found for this user'}), 404

    return jsonify([request.to_dict() for request in requests]), 200

# API route to get messages by request ID
@app.route('/api/get_messages/<int:req_id>', methods=['GET'])
def get_messages(req_id):
    messages = Messages.query.filter_by(request_id=req_id).all()

    if not messages:
        return jsonify({'error': 'No messages found for this request'}), 404

    return jsonify([message.to_dict() for message in messages]), 200

# API send message to request
@app.route('/api/send_message/<id>', methods=['POST'])
def send_message(id):
    data = request.get_json()

    message = data.get('message')
    request_id = data.get('request_id')

    if not message or not request_id:
        return jsonify({'error': 'Message, user ID, and request ID are required!'}), 400

    new_message = Messages(
        message=message,
        user_id=id,
        request_id=request_id,
    )

    try:
        db.session.add(new_message)
        db.session.commit()
    except SQLAlchemyError as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

    return jsonify({'message': 'Message sent successfully!'}), 200

# API route to create an admin user
@app.route('/create_admin', methods=['POST'])
def create_admin():
    admin_user = User(
        username='admin',
        email='admin@example.com',
        password=generate_password_hash('admin'),
        created_at=datetime.utcnow(),
        first_name='Admin',
        last_name='User'
    )

    db.session.add(admin_user)
    db.session.commit()

    return jsonify({"message": "Admin user added successfully!"}), 201

if __name__ == '__main__':
    app.run(debug=True)