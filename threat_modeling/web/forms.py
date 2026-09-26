"""WTForms for the Threat Modeling web application."""
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import StringField, TextAreaField, SelectField, BooleanField, IntegerField, FloatField
from wtforms.validators import DataRequired, Optional, NumberRange


class FileUploadForm(FlaskForm):
    """Form for uploading a .tm7 file and entering the system description."""
    tm7_file = FileField(
        'Upload .tm7 file',
        validators=[
            FileRequired(message='Please select a .tm7 file to upload'),
            FileAllowed(['tm7'], message='Only .tm7 files are allowed!')
        ],
        render_kw={'accept': '.tm7'}
    )
    system_description = TextAreaField(
        'System Description',
        validators=[DataRequired(message='System description is required')],
        render_kw={'rows': 10, 'placeholder': 'Describe the architecture, components, data flows, technologies used, etc...'}
    )


class AnalysisForm(FlaskForm):
    """Form for configuring threat analysis"""
    provider = SelectField(
        'AI Provider',
        choices=[
            ('', 'Select a provider...'),
            ('OPENAI', 'OpenAI'),
            ('GOOGLE', 'Google'),
            ('ANTHROPIC', 'Anthropic'),
            ('OLLAMA', 'Ollama (local)')
        ],
        validators=[DataRequired()],
        default=''
    )
    api_key = StringField(
        'API Key',
        validators=[Optional()],
        render_kw={'type': 'password', 'placeholder': 'Enter API key'}
    )
    model = SelectField(
        'AI Model',
        choices=[('', 'Select provider and fetch models first...')],
        validators=[Optional()],
        default=''
    )
    few_shot = BooleanField('Few Shot', default=False)
    chain_of_thoughts = BooleanField('Chain of Thoughts', default=False)


class RAGEnhancementForm(FlaskForm):
    """Form for RAG enhancement (number of NIST controls to retrieve per threat)."""
    k_controls = IntegerField(
        'Quantity of Controls',
        validators=[DataRequired(), NumberRange(min=1, max=20)],
        default=5
    )



class CoverageForm(FlaskForm):
    """Form for reference coverage: expected threats and which sources to check."""
    expected_threats = TextAreaField(
        'Expected Threats',
        validators=[DataRequired(message='Paste at least one expected threat')],
        render_kw={'rows': 8,
                   'placeholder': 'One expected threat per line, as written by the reference source.'}
    )
    include_tmt = BooleanField('TMT threats (from the .tm7)', default=True)
    include_ai = BooleanField('AI analysis threats', default=True)
    threshold = FloatField(
        'Score threshold',
        validators=[DataRequired(), NumberRange(min=0.0, max=1.0)],
        default=0.7
    )
