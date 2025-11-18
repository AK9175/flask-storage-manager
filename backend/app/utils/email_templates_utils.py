"""
Email template rendering and sending utilities.
"""
import os
from datetime import datetime
from jinja2 import Template
import logging

logger = logging.getLogger(__name__)

# Get the project root directory (3 levels up from this file: app/utils/email_templates_utils.py)
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
TEMPLATE_DIR = os.path.join(PROJECT_ROOT, 'email_templates')


def load_template(template_name: str) -> str:
    """Load an email template from file."""
    template_path = os.path.join(TEMPLATE_DIR, template_name)
    
    if not os.path.exists(template_path):
        logger.error(f"Template not found: {template_path}")
        raise FileNotFoundError(f"Email template '{template_name}' not found")
    
    with open(template_path, 'r') as f:
        return f.read()


def render_template(template_name: str, **context) -> str:
    """Render a template with the given context."""
    context['current_year'] = datetime.now().year
    template_content = load_template(template_name)
    template = Template(template_content)
    return template.render(**context)


def extract_subject(text_content: str) -> str:
    """Extract subject line from text template (first line starting with 'Subject:')."""
    for line in text_content.split('\n'):
        if line.startswith('Subject:'):
            return line.replace('Subject:', '').strip()
    return "Storage Manager"


def get_signup_invitation_emails(admin_email: str, signup_token: str, app_url: str) -> dict:
    """Generate signup invitation emails (text and HTML)."""
    signup_link = f"{app_url}/auth/user/signup?token={signup_token}"
    
    context = {
        'admin_email': admin_email,
        'signup_link': signup_link
    }
    
    # Render text version
    text_content = render_template('signup_invitation_text.txt', **context)
    subject = extract_subject(text_content)
    text_body = '\n'.join(text_content.split('\n')[1:]).strip()
    
    # Render HTML version
    html_body = render_template('signup_invitation_html.html', **context)
    
    return {
        'subject': subject,
        'text': text_body,
        'html': html_body
    }


def get_password_reset_emails(reset_token: str, app_url: str, is_admin: bool = False) -> dict:
    """Generate password reset emails (text and HTML)."""
    reset_link = f"{app_url}/auth/{'admin' if is_admin else 'user'}/reset-password?token={reset_token}"
    
    context = {
        'reset_link': reset_link
    }
    
    # Render text version
    text_content = render_template('password_reset_text.txt', **context)
    subject = extract_subject(text_content)
    text_body = '\n'.join(text_content.split('\n')[1:]).strip()
    
    # Render HTML version
    html_body = render_template('password_reset_html.html', **context)
    
    return {
        'subject': subject,
        'text': text_body,
        'html': html_body
    }
