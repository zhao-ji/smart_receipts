import os
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # 允许 HTTP 进行 OAuth

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from oauthlib.oauth2 import WebApplicationClient
import requests
import json
import os
from datetime import datetime
from config import Config
from apscheduler.schedulers.background import BackgroundScheduler
from azure.ai.formrecognizer import DocumentAnalysisClient
from azure.core.credentials import AzureKeyCredential
from openai import AzureOpenAI
from pprint import pprint

app = Flask(__name__)
app.config.from_object(Config)

# Initialize SQLAlchemy
db = SQLAlchemy(app)

# Initialize LoginManager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize OAuth 2.0 client
client = WebApplicationClient(app.config['GOOGLE_CLIENT_ID'])

# Initialize Azure Form Recognizer client
form_recognizer_client = DocumentAnalysisClient(
    endpoint=app.config['AZURE_FORM_ENDPOINT'],
    credential=AzureKeyCredential(app.config['AZURE_FORM_KEY'])
)

# Initialize Azure OpenAI
openai_client = AzureOpenAI(
    api_key=app.config['AZURE_OPENAI_KEY'],
    api_version="2023-05-15",
    azure_endpoint=app.config['AZURE_OPENAI_ENDPOINT']
)

# Create upload folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    name = db.Column(db.String(100))
    receipts = db.relationship('Receipt', backref='user', lazy=True)

class Receipt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    upload_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    image_path = db.Column(db.String(200))
    items = db.relationship('FoodItem', backref='receipt', lazy=True)

class FoodItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    receipt_id = db.Column(db.Integer, db.ForeignKey('receipt.id'), nullable=False)
    name = db.Column(db.String(100))
    price = db.Column(db.Float)
    expiry_date = db.Column(db.DateTime)
    calories = db.Column(db.Integer)
    storage_instructions = db.Column(db.Text)
    notes = db.Column(db.Text)
    recipes = db.Column(db.Text)  # 将存储 JSON 字符串
    notification_sent = db.Column(db.Boolean, default=False)

    def get_recipes(self):
        """获取食谱列表"""
        if self.recipes:
            return json.loads(self.recipes)
        return []

    def set_recipes(self, recipes_list):
        """设置食谱列表"""
        if recipes_list is None:
            recipes_list = []
        self.recipes = json.dumps(recipes_list)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    if current_user.is_authenticated:
        return render_template('dashboard.html')
    print(111111111111111)
    return render_template('index.html')

@app.route('/login')
def login():
    # Find out what URL to hit for Google login
    google_provider_cfg = requests.get('https://accounts.google.com/.well-known/openid-configuration').json()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    # Use library to construct the request for login and provide
    # scopes that let you retrieve user's profile from Google
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)

@app.route('/login/callback')
def callback():
    # Get authorization code Google sent back to you
    code = request.args.get("code")

    # Find out what URL to hit to get tokens that allow you to ask for
    # things on behalf of a user
    google_provider_cfg = requests.get('https://accounts.google.com/.well-known/openid-configuration').json()
    token_endpoint = google_provider_cfg["token_endpoint"]

    # Prepare and send request to get tokens
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code,
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(app.config['GOOGLE_CLIENT_ID'], app.config['GOOGLE_CLIENT_SECRET']),
    )

    # Parse the tokens
    client.parse_request_body_response(json.dumps(token_response.json()))

    # Now that we have tokens let's find and hit URL
    # from Google that gives you user's profile information,
    # including their Google Profile Image and Email
    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)

    # We want to make sure their email is verified.
    # The user authenticated with Google, authorized our
    # app, and now we've verified their email through Google!
    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]
        users_name = userinfo_response.json()["given_name"]
    else:
        return "User email not available or not verified by Google.", 400

    # Create a user in our db with the information provided
    # by Google
    user = User.query.filter_by(email=users_email).first()
    if not user:
        user = User(
            email=users_email,
            name=users_name
        )
        db.session.add(user)
        db.session.commit()

    # Begin user session by logging the user in
    login_user(user)

    # Send user back to homepage
    return redirect(url_for('index'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/upload', methods=['POST'])
@login_required
def upload_receipt():
    if 'receipt' not in request.files:
        flash('No file uploaded')
        return redirect(url_for('index'))

    file = request.files['receipt']
    if file.filename == '':
        flash('No file selected')
        return redirect(url_for('index'))

    # Save the file
    filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{file.filename}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    # Create receipt record
    receipt = Receipt(user_id=current_user.id, image_path=filepath)
    db.session.add(receipt)
    db.session.commit()

    # Process the receipt (implement this function)
    process_receipt(receipt.id)

    flash('Receipt uploaded and processed successfully')
    return redirect(url_for('index'))

@app.route('/delete_food_item/<int:item_id>', methods=['POST'])
@login_required
def delete_food_item(item_id):
    food_item = FoodItem.query.get_or_404(item_id)
    # 验证该食品项目属于当前用户
    receipt = Receipt.query.get(food_item.receipt_id)
    if receipt.user_id != current_user.id:
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))

    db.session.delete(food_item)
    db.session.commit()
    flash('Food item deleted successfully', 'success')
    return redirect(url_for('index'))

@app.route('/update_expiry/<int:item_id>', methods=['POST'])
@login_required
def update_expiry(item_id):
    food_item = FoodItem.query.get_or_404(item_id)
    receipt = Receipt.query.get(food_item.receipt_id)
    
    # 验证权限
    if receipt.user_id != current_user.id:
        flash('Unauthorized access', 'error')
        return redirect(url_for('index'))
    
    try:
        new_date = request.form.get('expiry_date')
        if new_date:
            food_item.expiry_date = datetime.strptime(new_date, '%Y-%m-%d')
            db.session.commit()
            flash('Expiration date updated successfully', 'success')
        else:
            flash('Invalid date format', 'error')
    except ValueError:
        flash('Invalid date format', 'error')
    
    return redirect(url_for('index'))

@app.route('/recipes')
@login_required
def recipes():
    # 获取用户的所有食材
    user_items = FoodItem.query.join(Receipt).filter(Receipt.user_id == current_user.id).all()
    ingredients = [item.name for item in user_items]
    
    # 使用 Azure OpenAI 生成菜谱推荐
    prompt = f"""Based on these ingredients: {', '.join(ingredients)}
    Suggest 5 recipes in JSON format. For each recipe, list required ingredients and mark which ones are missing from the user's ingredients.
    Format:
    {{
        "recipes": [
            {{
                "name": "Recipe Name",
                "description": "Brief description",
                "cooking_time": "30 mins",
                "difficulty": "Easy/Medium/Hard",
                "ingredients": [
                    {{"name": "ingredient1", "amount": "100g", "have": true}},
                    {{"name": "ingredient2", "amount": "2 tbsp", "have": false}}
                ],
                "instructions": ["step 1", "step 2", "step 3"]
            }}
        ]
    }}
    """
    
    try:
        response = openai_client.chat.completions.create(
            model=app.config['AZURE_OPENAI_DEPLOYMENT'],
            messages=[
                {"role": "system", "content": "You are a helpful chef who suggests recipes based on available ingredients."},
                {"role": "user", "content": prompt}
            ]
        )
        
        content = response.choices[0].message.content
        if content.startswith('```'):
            content = content.split('```')[1]
            if content.startswith('json'):
                content = content[4:]
        content = content.strip()
        
        recipes = json.loads(content).get('recipes', [])
        return render_template('recipes.html', recipes=recipes, ingredients=ingredients)
        
    except Exception as e:
        app.logger.error(f"Error generating recipes: {str(e)}")
        flash('Error generating recipes. Please try again later.', 'error')
        return redirect(url_for('index'))

def process_receipt(receipt_id):
    receipt = Receipt.query.get(receipt_id)

    # Use Azure Form Recognizer to extract items
    with open(receipt.image_path, "rb") as f:
        poller = form_recognizer_client.begin_analyze_document("prebuilt-receipt", f)
    result = poller.result()

    # Extract items from the receipt
    if result.documents:
        doc = result.documents[0]
        if doc.fields.get("Items"):
            items = doc.fields["Items"].value
            for item in items:
                # 获取商品名称和价格
                description = item.value.get("Description").value if item.value.get("Description") else "Unknown Item"
                total_price = float(item.value.get("TotalPrice").value) if item.value.get("TotalPrice") else 0.0

                # Process each item with Azure OpenAI
                food_info = get_food_info(description)

                food_item = FoodItem(
                    receipt_id=receipt_id,
                    name=description,
                    price=total_price,
                    expiry_date=food_info.get('expiry_date'),
                    calories=food_info.get('calories'),
                    storage_instructions=food_info.get('storage'),
                    notes=food_info.get('notes')
                )
                food_item.set_recipes(food_info.get('recipes', []))
                db.session.add(food_item)

    db.session.commit()

def get_food_info(food_name):
    prompt = f"""Analyze this food item: {food_name}
    Provide the following information in JSON format (do not include markdown code blocks):
    {{
        "expiry_date": "typical expiry timeframe (e.g., '7 days')",
        "calories": "calories per serving as a number",
        "storage": "storage instructions",
        "notes": "important notes",
        "recipes": ["recipe suggestion 1", "recipe suggestion 2"]
    }}"""
    
    response = openai_client.chat.completions.create(
        model=app.config['AZURE_OPENAI_DEPLOYMENT'],
        messages=[
            {"role": "system", "content": "You are a helpful food expert. Respond with JSON exactly matching the format specified, using the exact same field names."},
            {"role": "user", "content": prompt}
        ]
    )
    
    content = response.choices[0].message.content
    # 移除可能的 markdown 标记
    if content.startswith('```'):
        content = content.split('```')[1]
        if content.startswith('json'):
            content = content[4:]
    content = content.strip()
    
    try:
        food_info = json.loads(content)
        # 处理过期日期
        if isinstance(food_info.get('expiry_date'), str):
            try:
                # 将文本描述转换为实际日期
                expiry_text = food_info['expiry_date'].lower()
                days = 0
                if 'day' in expiry_text:
                    days = int(''.join(filter(str.isdigit, expiry_text)))
                elif 'week' in expiry_text:
                    days = int(''.join(filter(str.isdigit, expiry_text))) * 7
                elif 'month' in expiry_text:
                    days = int(''.join(filter(str.isdigit, expiry_text))) * 30
                elif 'year' in expiry_text:
                    days = int(''.join(filter(str.isdigit, expiry_text))) * 365
                
                if days > 0:
                    food_info['expiry_date'] = datetime.now() + timedelta(days=days)
                else:
                    food_info['expiry_date'] = None
            except:
                food_info['expiry_date'] = None
        
        # 处理卡路里
        if isinstance(food_info.get('calories'), str):
            try:
                calories = ''.join(filter(str.isdigit, food_info['calories']))
                food_info['calories'] = int(calories) if calories else None
            except:
                food_info['calories'] = None
        
        # 确保其他字段存在
        food_info['storage'] = food_info.get('storage', 'Store properly according to package instructions')
        food_info['notes'] = food_info.get('notes', 'Information not available')
        food_info['recipes'] = food_info.get('recipes', [])
        if isinstance(food_info['recipes'], str):
            food_info['recipes'] = [food_info['recipes']]
        
        return food_info
    except json.JSONDecodeError:
        # 如果解析失败，返回一个基本的结构
        return {
            "expiry_date": None,
            "calories": None,
            "storage": "Store properly according to package instructions",
            "notes": "Information not available",
            "recipes": []
        }

def check_expiring_items():
    # Check for items expiring in 3 days or today
    # Implement notification logic here
    pass

# Initialize scheduler
scheduler = BackgroundScheduler()
scheduler.add_job(func=check_expiring_items, trigger="interval", hours=24)
scheduler.start()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
