from flask import Flask, jsonify, request, render_template
from models import Message, db, User, FacebookMarketingRequest
from config import Config
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required, JWTManager, unset_jwt_cookies

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

    new_user = User(
        username=data['username'],
        email=data['email'],
        password=hashed_password
    )
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

# API route to submit facebook marketing request
@app.route('/api/submit_facebook_request', methods=['POST'])
def submit_facebook_request():
    data = request.get_json()

    page_name = data.get('page_name')
    page_url = data.get('page_url')
    campaign_objective = data.get('campaign_objective')
    target_audience = data.get('target_audience')
    budget = data.get('budget')
    duration = data.get('duration')
    user_id = data.get('user_id')

    if not all([page_name, page_url, campaign_objective, budget, duration, user_id]):
        return jsonify({'error': 'Page name, URL, campaign objective, budget, duration, and user ID are required!'}), 400

    new_request = FacebookMarketingRequest(
        page_name=page_name,
        page_url=page_url,
        campaign_objective=campaign_objective,
        target_audience=target_audience,
        budget=float(budget),
        duration=int(duration)
    )

    db.session.add(new_request)
    db.session.commit()

    new_message = Message(
        content=f"New Facebook marketing request submitted:\n"
                f"Page Name: {page_name}\n"
                f"Page URL: {page_url}\n"
                f"Objective: {campaign_objective}\n"
                f"Target Audience: {target_audience}\n"
                f"Budget: ${budget}\n"
                f"Duration: {duration} days",
        user_id=user_id,
        request_id=new_request.id,
    )

    db.session.add(new_message)
    db.session.commit()

    return jsonify({'message': 'Facebook marketing request submitted successfully!'}), 200

# API route to submit instagram marketing request
@app.route('/api/submit_instagram_request', methods=['POST'])
def submit_instagram_request():
    data = request.get_json()

    page_name = data.get('page_name')
    page_url = data.get('page_url')
    campaign_objective = data.get('campaign_objective')
    target_audience = data.get('target_audience')
    budget = data.get('budget')
    duration = data.get('duration')
    user_id = data.get('user_id')

    if not page_name or not page_url or not campaign_objective or not budget or not duration or not user_id:
        return jsonify({'error': 'Page name, URL, and campaign objective are required!'}), 400

    new_request = InstagramMarketingRequest(
        page_name=page_name,
        page_url=page_url,
        campaign_objective=campaign_objective,
        target_audience=target_audience,
        budget=float(budget),
        duration=int(duration)
    )

    db.session.add(new_request)
    db.session.commit()

    new_message = Message(
        content=f"New Instagram marketing request submitted:\n"
                f"Page Name: {page_name}\n"
                f"Page URL: {page_url}\n"
                f"Objective: {campaign_objective}\n"
                f"Target Audience: {target_audience}\n"
                f"Budget: ${budget}\n"
                f"Duration: {duration} days",
        user_id=user_id,
        request_id=new_request.id,
    )

    db.session.add(new_message)
    db.session.commit()

    return jsonify({'message': 'Instagram marketing request submitted successfully!'}), 200

# API route to submit Snapchat marketing request
@app.route('/api/submit_snapchat_request', methods=['POST'])
def submit_snapchat_request():
    data = request.get_json()

    page_name = data.get('page_name')
    page_url = data.get('page_url')
    campaign_objective = data.get('campaign_objective')
    target_audience = data.get('target_audience')
    budget = data.get('budget')
    duration = data.get('duration')
    user_id = data.get('user_id')

    if not page_name or not page_url or not campaign_objective or not budget or not duration or not user_id:
        return jsonify({'error': 'Page name, URL, and campaign objective are required!'}), 400

    new_request = SnapchatMarketingRequest(
        page_name=page_name,
        page_url=page_url,
        campaign_objective=campaign_objective,
        target_audience=target_audience,
        budget=float(budget),
        duration=int(duration)
    )

    db.session.add(new_request)
    db.session.commit()

    new_message = Message(
        content=f"New Snapchat marketing request submitted:\n"
                f"Page Name: {page_name}\n"
                f"Page URL: {page_url}\n"
                f"Objective: {campaign_objective}\n"
                f"Target Audience: {target_audience}\n"
                f"Budget: ${budget}\n"
                f"Duration: {duration} days",
        user_id=user_id,
        request_id=new_request.id,
    )

    db.session.add(new_message)
    db.session.commit()

    return jsonify({'message': 'Snapchat marketing request submitted successfully!'}), 200

# API route to submit TikTok marketing request
@app.route('/api/submit_tiktok_request', methods=['POST'])
def submit_tiktok_request():
    data = request.get_json()

    page_name = data.get('page_name')
    page_url = data.get('page_url')
    campaign_objective = data.get('campaign_objective')
    target_audience = data.get('target_audience')
    budget = data.get('budget')
    duration = data.get('duration')
    user_id = data.get('user_id')

    if not page_name or not page_url or not campaign_objective or not budget or not duration or not user_id:
        return jsonify({'error': 'Page name, URL, and campaign objective are required!'}), 400

    new_request = TiktokMarketingRequest(
        page_name=page_name,
        page_url=page_url,
        campaign_objective=campaign_objective,
        target_audience=target_audience,
        budget=float(budget),
        duration=int(duration)
    )

    db.session.add(new_request)
    db.session.commit()

    new_message = Message(
        content=f"New TikTok marketing request submitted:\n"
                f"Page Name: {page_name}\n"
                f"Page URL: {page_url}\n"
                f"Objective: {campaign_objective}\n"
                f"Target Audience: {target_audience}\n"
                f"Budget: ${budget}\n"
                f"Duration: {duration} days",
        user_id=user_id,
        request_id=new_request.id,
    )

    db.session.add(new_message)
    db.session.commit()

    return jsonify({'message': 'TikTok marketing request submitted successfully!'}), 200

@app.route('/users')
def manage_users():
    users = User.query.all()
    return render_template('manage_users.html', users=users)

if __name__ == '__main__':
    app.run(debug=True)