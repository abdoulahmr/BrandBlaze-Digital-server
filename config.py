class Config:
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'mysql+mysqlconnector://admin:Red$hop2024!@localhost/djalalservices'
    SQLALCHEMY_DATABASE_URI = "mysql+mysqlconnector://{username}:{password}@{hostname}/{databasename}".format(
        username="djalalservices",
        password="mysqladmin",
        hostname="djalalservices.mysql.pythonanywhere-services.com",
        databasename="djalalservices$default"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = 'your_secret_key'
    JWT_SECRET_KEY = 'jwt_secret'
    ALLOWED_EXTENSIONS = {'svg', 'png', 'jpg', 'jpeg'}
    UPLOAD_FOLDER = 'static/uploads'

    def allowed_file(filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS