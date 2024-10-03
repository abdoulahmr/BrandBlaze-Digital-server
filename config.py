class Config:
    DEBUG = True

    # MySQL Configuration
    SQLALCHEMY_DATABASE_URI = "mysql+mysqlconnector://{username}:{password}@{hostname}/{databasename}".format(
        username="djalalservices",
        password="mysqladmin",
        hostname="djalalservices.mysql.pythonanywhere-services.com",
        databasename="djalalservices$default"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Flask secret keys and allowed file types
    SECRET_KEY = 'your_secret_key'
    JWT_SECRET_KEY = 'jwt_secret'
    ALLOWED_EXTENSIONS = {'svg', 'png', 'jpg', 'jpeg'}
    UPLOAD_FOLDER = 'static/uploads'


    # Function to check file type
    def allowed_file(filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS
