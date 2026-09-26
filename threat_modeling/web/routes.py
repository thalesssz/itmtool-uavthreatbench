"""Flask routes - Upload, analysis, results, comparison, RAG enhance, and download."""
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, send_file, jsonify
import json
import os
import tempfile
import pandas as pd
from io import BytesIO

from threat_modeling.web.forms import FileUploadForm, AnalysisForm, CoverageForm
from threat_modeling.services.threat_model_service import ThreatModelService
from threat_modeling.services.analysis_service import AnalysisService
from threat_modeling.services.rag_service import RAGService
from threat_modeling.services.comparison_service import ComparisonService
from threat_modeling.services.coverage_service import CoverageService, DEFAULT_THRESHOLD
from threat_modeling.config.settings import PAID_PROVIDER, PAID_API_KEY, PAID_ANALYST_MODEL, PAID_JUDGE_MODEL
from threat_modeling.api.model_lister import list_openai_models, list_google_models, list_anthropic_models, list_ollama_models
from threat_modeling.api.llm_client import LLMClient
from threat_modeling.api.message_builder import generate_rag_messages
from threat_modeling.models.rag_models import RAGResponse
from threat_modeling.config.settings import DATA_DIR

main_bp = Blueprint('main', __name__)


@main_bp.route('/', methods=['GET', 'POST'])
def index():
    """Render upload form; on POST, parse .tm7, validate, store in session, redirect to select_diagram or analyze."""
    form = FileUploadForm()

    if request.method == 'POST':
        if form.validate_on_submit():
            try:
                # Clear previous session data for new upload
                keys_to_clear = [
                    'threat_model_data', 'json_data', 'threat_data',
                    'selected_diagram_index', 'analysis_ready',
                    'analysis_results', 'analysis_df', 'analysis_complete',
                    'analysis_df_rag', 'rag_complete', 'system_description', 'file_name', 'xml_content'
                ]
                for key in keys_to_clear:
                    session.pop(key, None)

                # Clear dynamic comparison keys
                for key in list(session.keys()):
                    if key.startswith('comparison_'):
                        session.pop(key, None)

                # Process uploaded file
                uploaded_file = form.tm7_file.data
                system_description = form.system_description.data

                if not uploaded_file:
                    flash('No file uploaded', 'error')
                    return render_template('index.html', form=form)

                if not system_description or not system_description.strip():
                    flash('System description is required', 'error')
                    return render_template('index.html', form=form)

                # Read file content
                uploaded_file.seek(0)  # Reset file pointer
                xml_content = uploaded_file.read().decode('utf-8')

                if not xml_content or len(xml_content.strip()) == 0:
                    flash('Uploaded file is empty', 'error')
                    return render_template('index.html', form=form)

                # Parse threat model
                threat_model = ThreatModelService.parse_tm7_file(xml_content)

                # Validate
                is_valid, error_msg = ThreatModelService.validate_threat_model(threat_model)
                if not is_valid:
                    flash(error_msg, 'error')
                    return render_template('index.html', form=form)

                # Store in session (serialize threat_model)
                # Note: Flask session can't store complex objects, so we'll store the parsed data
                session['threat_model_data'] = {
                    'version': threat_model.version,
                    'num_diagrams': len(threat_model.diagrams),
                    'diagram_names': [d.name for d in threat_model.diagrams],
                    'num_threats': len(threat_model.threats)
                }
                session['system_description'] = system_description
                session['file_name'] = uploaded_file.filename
                session['xml_content'] = xml_content  # Store XML for re-parsing if needed

                # Get selected diagram (default to first)
                selected_idx = 0
                if len(threat_model.diagrams) > 1:
                    # If multiple diagrams, redirect to selection page
                    return redirect(url_for('main.select_diagram'))

                # Process single diagram
                json_data = ThreatModelService.get_diagram_json(threat_model, selected_idx)
                threat_data = ThreatModelService.get_threat_data_json(threat_model)

                session['json_data'] = json_data
                session['threat_data'] = threat_data
                session['selected_diagram_index'] = selected_idx
                session['analysis_ready'] = True

                flash('File processed successfully!', 'success')
                return redirect(url_for('main.select_diagram'))

            except Exception as e:
                flash(f'Error processing file: {str(e)}', 'error')
                import traceback
                print(f"Error details: {traceback.format_exc()}")
        else:
            # Form validation failed
            flash('Please check the form for errors', 'error')
            for field, errors in form.errors.items():
                for error in errors:
                    flash(f'{field}: {error}', 'error')

    return render_template('index.html', form=form)


@main_bp.route('/select-diagram', methods=['GET', 'POST'])
def select_diagram():
    """Let user choose one diagram when the .tm7 file contains multiple; store selection and redirect to analyze."""
    if 'xml_content' not in session:
        flash('Please upload a file first', 'error')
        return redirect(url_for('main.index'))

    # Re-parse threat model from stored XML
    xml_content = session['xml_content']
    threat_model = ThreatModelService.parse_tm7_file(xml_content)

    if request.method == 'POST':
        selected_idx = int(request.form.get('diagram_index', 0))

        # Process selected diagram
        json_data = ThreatModelService.get_diagram_json(threat_model, selected_idx)
        threat_data = ThreatModelService.get_threat_data_json(threat_model)

        session['json_data'] = json_data
        session['threat_data'] = threat_data
        session['selected_diagram_index'] = selected_idx
        session['analysis_ready'] = True

        flash('Diagram selected successfully!', 'success')
        return redirect(url_for('main.analyze'))

    threat_model_data = {
        'diagrams': [{'name': d.name, 'index': i} for i, d in enumerate(threat_model.diagrams)]
    }
    return render_template('select_diagram.html', threat_model_data=threat_model_data)


@main_bp.route('/api/diagram-json/<int:diagram_index>')
def get_diagram_json(diagram_index):
    """Return diagram dataflow JSON for the given diagram index (requires session with xml_content)."""
    if 'xml_content' not in session:
        return jsonify({'error': 'No file uploaded'}), 400

    try:
        # Re-parse threat model from stored XML
        xml_content = session['xml_content']
        threat_model = ThreatModelService.parse_tm7_file(xml_content)

        # Validate diagram index
        if diagram_index < 0 or diagram_index >= len(threat_model.diagrams):
            return jsonify({'error': 'Invalid diagram index'}), 400

        # Get JSON data for the diagram
        json_data = ThreatModelService.get_diagram_json(threat_model, diagram_index)

        return jsonify({
            'success': True,
            'diagram_name': threat_model.diagrams[diagram_index].name,
            'json_data': json_data
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@main_bp.route('/api/list-models', methods=['POST'])
def list_models():
    """Return list of models for the given provider (JSON body: provider, optional api_key)."""
    try:
        data = request.get_json()
        provider = data.get('provider')
        api_key = data.get('api_key')

        if not provider:
            return jsonify({'error': 'Provider is required'}), 400

        if provider == 'OPENAI':
            models = list_openai_models(api_key=api_key)
        elif provider == 'GOOGLE':
            models = list_google_models(api_key=api_key)
        elif provider == 'ANTHROPIC':
            models = list_anthropic_models(api_key=api_key)
        elif provider == 'OLLAMA':
            # Local server: no API key involved.
            models = list_ollama_models()
        else:
            return jsonify({'error': f'Unknown provider: {provider}'}), 400

        return jsonify({
            'success': True,
            'models': models
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@main_bp.route('/api/diagram-threats/<int:diagram_index>')
def get_diagram_threats(diagram_index):
    """Return threats for the given diagram as JSON (list of threat records with DataFlow info)."""
    if 'xml_content' not in session:
        return jsonify({'error': 'No file uploaded'}), 400

    try:
        # Re-parse threat model from stored XML
        xml_content = session['xml_content']
        threat_model = ThreatModelService.parse_tm7_file(xml_content)

        # Validate diagram index
        if diagram_index < 0 or diagram_index >= len(threat_model.diagrams):
            return jsonify({'error': 'Invalid diagram index'}), 400

        # Get threats for the diagram
        diagram_threats = ThreatModelService.get_diagram_threats(threat_model, diagram_index)
        selected_diagram = threat_model.diagrams[diagram_index]

        # Create a map of flow_guid -> dataflow info (name, source, target)
        flow_info_map = {}
        elements_map = {elem.guid: elem for elem in selected_diagram.elements}

        for flow in selected_diagram.dataflows:
            source_element = elements_map.get(flow.source_guid)
            target_element = elements_map.get(flow.target_guid)
            source_name = source_element.name if source_element else f"Unknown ({flow.source_guid})"
            target_name = target_element.name if target_element else f"Unknown ({flow.target_guid})"

            flow_info_map[flow.guid] = {
                'name': flow.name,
                'source': source_name,
                'target': target_name,
                'display': f"{source_name} → {target_name} ({flow.name})"
            }

        # Convert to JSON format
        threats_json = ThreatModelService.get_diagram_threats_json(threat_model, diagram_index)

        # Generate DataFrame for display
        threat_df = ThreatModelService.generate_threat_dataframe(threats_json)

        # Add DataFlow information to the DataFrame
        # The DataFrame should have a 'DataFlow' column with flow_guid values
        # Map them to the dataflow name only
        if 'DataFlow' in threat_df.columns:
            threat_df['DataFlow'] = threat_df['DataFlow'].apply(
                lambda flow_guid: flow_info_map.get(flow_guid, {}).get('name', flow_guid if flow_guid else 'N/A')
            )
        else:
            # If DataFlow column doesn't exist, create it from the threats
            # This should not happen normally, but handle it as fallback
            threat_df['DataFlow'] = [
                flow_info_map.get(threat.flow_guid, {}).get('name', threat.flow_guid if threat.flow_guid else 'N/A')
                for threat in diagram_threats
            ]

        return jsonify({
            'success': True,
            'diagram_name': threat_model.diagrams[diagram_index].name,
            'threats_count': len(diagram_threats),
            'threats': threat_df.to_dict('records')
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


def _judge_config():
    """
    Provider, model and key used to judge threats (TMT comparison and coverage).

    In paid mode the judge is a different model from the analyst, chosen on the
    analysis screen, so no model grades its own output. In local mode one model
    does everything.
    """
    if session.get('paid_mode'):
        return PAID_PROVIDER, session.get('judge_model') or PAID_JUDGE_MODEL, PAID_API_KEY
    return (session.get('selected_provider', 'OLLAMA'),
            session.get('selected_model', ''),
            session.get('api_key', None))


@main_bp.route('/analyze', methods=['GET', 'POST'])
def analyze():
    """Render analysis form (provider, model, API key, few-shot, CoT); on POST, run analysis and redirect to results."""
    if 'analysis_ready' not in session or not session.get('analysis_ready'):
        flash('Please upload and process a file first', 'error')
        return redirect(url_for('main.index'))

    form = AnalysisForm()

    # Get threat model info for display (needed for error rendering)
    threat_model_data = session.get('threat_model_data', {})

    # Pre-fill form with session data if available
    if request.method == 'GET':
        form.provider.data = session.get('selected_provider', '')
        form.api_key.data = session.get('api_key', '')
        form.model.data = session.get('selected_model', '')
        form.few_shot.data = session.get('few_shot', False)
        form.chain_of_thoughts.data = session.get('chain_of_thoughts', False)

    # Handle POST request
    if request.method == 'POST':
        # Get form data directly from request.form to ensure we capture dynamic fields
        provider = request.form.get('provider', '')
        model_option = request.form.get('model', '')
        api_key = request.form.get('api_key', '') or None
        few_shot = request.form.get('few_shot') == 'y'
        cot = request.form.get('chain_of_thoughts') == 'y'

        # Paid mode: key taken from the server (never typed into the screen), and
        # the analyst and the judge are chosen separately. Local mode keeps one
        # model for everything.
        paid_mode = request.form.get('run_paid') == '1'
        judge_model = None
        if paid_mode:
            if not PAID_API_KEY:
                flash('No server-side API key configured (PAID_API_KEY or OPENAI_API_KEY)', 'error')
                return render_template('analyze.html', form=form, threat_model_data=threat_model_data,
                                       paid_analyst_model=PAID_ANALYST_MODEL, paid_judge_model=PAID_JUDGE_MODEL)
            provider, api_key = PAID_PROVIDER, PAID_API_KEY
            model_option = request.form.get('paid_analyst_model', '').strip() or PAID_ANALYST_MODEL
            judge_model = request.form.get('paid_judge_model', '').strip() or PAID_JUDGE_MODEL

        # Validate required fields
        if not provider or provider == '':
            flash('Please select a provider', 'error')
            return render_template('analyze.html', form=form, threat_model_data=threat_model_data,
                                       paid_analyst_model=PAID_ANALYST_MODEL, paid_judge_model=PAID_JUDGE_MODEL)

        if not model_option or model_option == '':
            flash('Please select a model', 'error')
            return render_template('analyze.html', form=form, threat_model_data=threat_model_data,
                                       paid_analyst_model=PAID_ANALYST_MODEL, paid_judge_model=PAID_JUDGE_MODEL)

        # Ollama runs locally and has no API key; requiring one would make the
        # provider unusable even though LLMClient already supports it.
        if not api_key and provider != 'OLLAMA':
            flash('Please enter an API key', 'error')
            return render_template('analyze.html', form=form, threat_model_data=threat_model_data,
                                       paid_analyst_model=PAID_ANALYST_MODEL, paid_judge_model=PAID_JUDGE_MODEL)

        try:
            # Store in session
            session['selected_provider'] = provider
            session['selected_model'] = model_option
            session['api_key'] = api_key
            session['few_shot'] = few_shot
            session['chain_of_thoughts'] = cot
            session['paid_mode'] = paid_mode
            session['judge_model'] = judge_model if paid_mode else model_option

            # Get data from session
            json_data = session.get('json_data', {})
            system_desc = session.get('system_description', '')

            if not json_data:
                flash('No threat model data available', 'error')
                return redirect(url_for('main.index'))

            # Run analysis
            analysis_service = AnalysisService()
            results = analysis_service.run_analysis(
                interactions=json_data,
                system_description=system_desc,
                provider=provider,
                model_name=model_option,
                few_shot=few_shot,
                cot=cot,
                api_key=api_key,
                server_ip=None,  # Not used for cloud providers
                verbose=False
            )

            # Generate DataFrame
            df = analysis_service.generate_dataframe(
                interactions=json_data,
                results=results,
                provider=provider,
                model_name=model_option,
                save=True
            )

            # Store results in session
            session['analysis_results'] = results
            session['analysis_df'] = df.to_dict('records')
            session['analysis_complete'] = True

            flash(f'Analysis completed successfully with {model_option}!', 'success')
            return redirect(url_for('main.results'))

        except Exception as e:
            flash(f'Error during analysis: {str(e)}', 'error')
            import traceback
            print(f"Error details: {traceback.format_exc()}")

    return render_template('analyze.html', form=form, threat_model_data=threat_model_data,
                                       paid_analyst_model=PAID_ANALYST_MODEL, paid_judge_model=PAID_JUDGE_MODEL)


@main_bp.route('/results')
def results():
    """Render analysis results table (and optional RAG column if RAG enhance was run)."""
    if 'analysis_complete' not in session or not session.get('analysis_complete'):
        flash('Please run analysis first', 'error')
        return redirect(url_for('main.analyze'))

    analysis_df = session.get('analysis_df', [])
    results_data = session.get('analysis_results', [])

    return render_template('results.html',
                         analysis_df=analysis_df,
                         results_data=results_data,
                         model_name=session.get('selected_model', 'unknown'))


@main_bp.route('/compare')
def compare():
    """Run or reuse comparison of TMT vs AI threats; render similar, TMT-only, and AI-only sections."""
    if 'analysis_complete' not in session or not session.get('analysis_complete'):
        flash('Please run analysis first', 'error')
        return redirect(url_for('main.analyze'))

    if 'xml_content' not in session:
        flash('Please upload a file first', 'error')
        return redirect(url_for('main.index'))

    try:
        # Get diagram index from session
        diagram_index = session.get('selected_diagram_index', 0)

        # Get TMT threats
        xml_content = session['xml_content']
        threat_model = ThreatModelService.parse_tm7_file(xml_content)

        # Validate diagram index
        if diagram_index < 0 or diagram_index >= len(threat_model.diagrams):
            flash('Invalid diagram index', 'error')
            return redirect(url_for('main.results'))

        # Get threats for the diagram
        threats_json = ThreatModelService.get_diagram_threats_json(threat_model, diagram_index)
        tmt_threats_df = ThreatModelService.generate_threat_dataframe(threats_json)

        # Add DataFlow name to TMT DataFrame
        selected_diagram = threat_model.diagrams[diagram_index]
        elements_map = {elem.guid: elem for elem in selected_diagram.elements}
        flow_info_map = {}

        for flow in selected_diagram.dataflows:
            flow_info_map[flow.guid] = flow.name

        if 'DataFlow' in tmt_threats_df.columns:
            tmt_threats_df['DataFlow'] = tmt_threats_df['DataFlow'].apply(
                lambda flow_guid: flow_info_map.get(flow_guid, flow_guid if flow_guid else 'N/A')
            )

        # Get AI results
        analysis_df = pd.DataFrame(session.get('analysis_df', []))

        if analysis_df.empty:
            flash('No analysis data available', 'error')
            return redirect(url_for('main.results'))

        # The judge: a separate model in paid mode, the analysis model otherwise
        provider, model_name, api_key = _judge_config()

        if not model_name:
            flash('No model selected', 'error')
            return redirect(url_for('main.results'))

        # Check if comparison already exists in session (one per analyst and judge)
        comparison_key = f"comparison_{diagram_index}_{session.get('selected_model', '')}_{model_name}"
        session['comparison_last_key'] = comparison_key
        if comparison_key in session:
            comparison_df = pd.DataFrame(session[comparison_key])
        else:
            # Run comparison
            comparison_service = ComparisonService()
            comparison_df = comparison_service.run_comparison(
                tmt_threats_df=tmt_threats_df,
                ai_results_df=analysis_df,
                provider=provider,
                model_name=model_name,
                api_key=api_key,
                server_ip=None
            )

            # Store in session
            session[comparison_key] = comparison_df.to_dict('records')

        # Separate results by source
        similar_threats = comparison_df[comparison_df['source'] == 'both'].copy()
        similar_threats = similar_threats[similar_threats['is_similar'] == True]

        tmt_only = comparison_df[comparison_df['source'] == 'tmt_only'].copy()
        ai_only = comparison_df[comparison_df['source'] == 'ai_only'].copy()

        # Convert to dict for template
        return render_template('compare.html',
                             similar_threats=similar_threats.to_dict('records'),
                             tmt_only=tmt_only.to_dict('records'),
                             ai_only=ai_only.to_dict('records'),
                             model_name=session.get('selected_model', ''),
                             judge_name=model_name,
                             diagram_name=threat_model.diagrams[diagram_index].name)

    except Exception as e:
        flash(f'Error during comparison: {str(e)}', 'error')
        import traceback
        print(f"Error details: {traceback.format_exc()}")
        return redirect(url_for('main.results'))


@main_bp.route('/rag-enhance', methods=['POST'])
def rag_enhance():
    """Apply RAG enhancement (k_controls from form); add NIST controls column and redirect to results."""
    if 'analysis_complete' not in session or not session.get('analysis_complete'):
        flash('Please run analysis first', 'error')
        return redirect(url_for('main.analyze'))

    try:
        k_controls = int(request.form.get('k_controls', 5))

        # Get analysis dataframe
        analysis_df = pd.DataFrame(session.get('analysis_df', []))

        if analysis_df.empty:
            flash('No analysis data available', 'error')
            return redirect(url_for('main.results'))

        # Get provider, model, and API key from session (same as used in analysis)
        rag_provider = session.get('selected_provider', 'OLLAMA')
        rag_model = session.get('selected_model', '')
        rag_api_key = session.get('api_key', None)

        if not rag_model:
            flash('No model selected for RAG enhancement', 'error')
            return redirect(url_for('main.results'))

        # Initialize RAG service and LLM client
        rag_service = RAGService(provider=rag_provider, api_key=rag_api_key)
        llm_client = LLMClient(
            provider=rag_provider,
            model_name=rag_model,
            api_key=rag_api_key,
            server_ip=None  # Not used for cloud providers
        )

        rag_results = []

        for idx, row in analysis_df.iterrows():
            category = row.get('category', '')
            description = row.get('description', '')

            try:
                # Search for relevant NIST controls using RAG
                question = f"{category}: {description}"
                rag_docs = rag_service.search(question, k=k_controls)

                # Generate messages using message_builder
                messages = generate_rag_messages(category, description, rag_docs)

                # Call LLM with structured output using Pydantic model
                rag_response = llm_client.invoke_with_structure(messages, RAGResponse)
                print(f"RAG Response (Pydantic): {rag_response}")

                # Parse response and extract controls using RAGService
                controls_text = rag_service.parse_llm_response(rag_response)
                rag_results.append(controls_text)

            except Exception as e:
                print(f"Error processing threat {idx}: {str(e)}")
                import traceback
                print(f"Traceback: {traceback.format_exc()}")
                rag_results.append("")

        # Add RAG results
        analysis_df['rag_nist'] = rag_results

        # Store enhanced results
        session['analysis_df_rag'] = analysis_df[['interaction_source', 'interaction_target',
                                                   'data_flow_name', 'category', 'description', 'rag_nist']].to_dict('records')
        session['rag_complete'] = True

        flash('RAG enhancement completed successfully!', 'success')
        return redirect(url_for('main.results'))

    except Exception as e:
        flash(f'Error during RAG enhancement: {str(e)}', 'error')
        import traceback
        print(f"Error details: {traceback.format_exc()}")
        return redirect(url_for('main.results'))


def _coverage_comparison(runs):
    """
    Build one row per (reference threat, source) with the score of every judge
    that has run, so a free local judge and a paid one can be read side by side.
    """
    linhas = {}
    for judge, run in runs.items():
        for row in run.get('rows', []):
            chave = (row['expected_index'], row['source'])
            item = linhas.setdefault(chave, {
                'expected_index': row['expected_index'],
                'expected_threat': row['expected_threat'],
                'source': row['source'],
                'scores': {},
                'covered': {}
            })
            item['scores'][judge] = row['best_score']
            item['covered'][judge] = row['covered']
    return [linhas[k] for k in sorted(linhas)]


@main_bp.route('/coverage', methods=['GET', 'POST'])
def coverage():
    """
    Check reference threats (e.g. the expected threats of a benchmark scenario)
    against the TMT threats and the AI analysis, using an LLM judge.

    ComparisonService pairs TMT and AI threats by (dataflow, category); reference
    threats have neither, so CoverageService judges them by description. Results
    are kept per judge model, which is what makes the free vs paid comparison.
    """
    if not session.get('analysis_complete'):
        flash('Please run analysis first', 'error')
        return redirect(url_for('main.analyze'))

    form = CoverageForm()

    if form.validate_on_submit():
        expected = [line.strip() for line in form.expected_threats.data.splitlines() if line.strip()]
        threshold = form.threshold.data or DEFAULT_THRESHOLD
        run_paid = request.form.get('run_paid') == '1'

        if run_paid:
            if not PAID_API_KEY:
                flash('No server-side API key configured (PAID_API_KEY or OPENAI_API_KEY)', 'error')
                return redirect(url_for('main.coverage'))
            provider, api_key = PAID_PROVIDER, PAID_API_KEY
            # The field comes pre-filled with the judge chosen on the analysis screen.
            model_name = request.form.get('judge_model', '').strip() or PAID_JUDGE_MODEL
        else:
            provider, model_name, api_key = _judge_config()

        sources = {}
        try:
            if form.include_tmt.data and 'xml_content' in session:
                threat_model = ThreatModelService.parse_tm7_file(session['xml_content'])
                diagram_index = session.get('selected_diagram_index', 0)
                tmt_threats = ThreatModelService.get_diagram_threats(threat_model, diagram_index)
                texts = [t.description for t in tmt_threats if t.description]
                if texts:
                    sources['TMT'] = texts

            if form.include_ai.data:
                texts = [row.get('description') for row in session.get('analysis_df', []) if row.get('description')]
                if texts:
                    sources['AI analysis'] = texts

            if not sources:
                flash('No threats available in the selected sources', 'error')
                return redirect(url_for('main.coverage'))

            coverage_service = CoverageService()
            pairs_df, coverage_df = coverage_service.run_coverage(
                expected_threats=expected,
                sources=sources,
                provider=provider,
                model_name=model_name,
                api_key=api_key,
                server_ip=None,
                scenario_context=session.get('system_description', ''),
                threshold=threshold
            )
            summary_df = CoverageService.summarize(pairs_df, coverage_df, threshold)

            runs = session.get('coverage_runs', {})
            runs[model_name] = {
                'rows': coverage_df.to_dict('records'),
                'summary': summary_df.to_dict('records'),
                'threshold': threshold,
                'paid': run_paid
            }
            session['coverage_runs'] = runs
            session['coverage_last'] = model_name
            session['coverage_expected_text'] = form.expected_threats.data
            session['coverage_threshold'] = threshold
            session['coverage_complete'] = True

            flash(f'Coverage completed with {model_name}!', 'success')
            return redirect(url_for('main.coverage'))

        except Exception as e:
            flash(f'Error during coverage: {str(e)}', 'error')
            import traceback
            print(f"Error details: {traceback.format_exc()}")

    if request.method == 'GET':
        form.expected_threats.data = session.get('coverage_expected_text', '')
        form.threshold.data = session.get('coverage_threshold', DEFAULT_THRESHOLD)

    runs = session.get('coverage_runs', {})
    last = session.get('coverage_last')
    return render_template('coverage.html',
                           form=form,
                           runs=runs,
                           judges=list(runs.keys()),
                           current=runs.get(last),
                           current_judge=last,
                           comparison=_coverage_comparison(runs) if len(runs) > 1 else [],
                           paid_mode=session.get('paid_mode', False),
                           analyst_model=session.get('selected_model', 'the selected model'),
                           judge_default=(session.get('judge_model') if session.get('paid_mode') else None) or PAID_JUDGE_MODEL,
                           local_model=session.get('selected_model', 'the selected model'),
                           threshold=session.get('coverage_threshold', DEFAULT_THRESHOLD))


@main_bp.route('/download/<format_type>')
def download(format_type):
    """Send file download for format_type: json, csv, rag_json, rag_csv, or comparison_csv."""
    if format_type == 'json':
        if 'analysis_df' not in session:
            flash('No results available', 'error')
            return redirect(url_for('main.results'))

        df = pd.DataFrame(session.get('analysis_df', []))
        json_str = df.to_json(orient='records', indent=2)

        return send_file(
            BytesIO(json_str.encode()),
            mimetype='application/json',
            as_attachment=True,
            download_name=f"threat_analysis_{session.get('selected_model', 'unknown')}.json"
        )

    elif format_type == 'csv':
        if 'analysis_df' not in session:
            flash('No results available', 'error')
            return redirect(url_for('main.results'))

        df = pd.DataFrame(session.get('analysis_df', []))
        csv_str = df.to_csv(index=False)

        return send_file(
            BytesIO(csv_str.encode()),
            mimetype='text/csv',
            as_attachment=True,
            download_name=f"threat_analysis_{session.get('selected_model', 'unknown')}.csv"
        )

    elif format_type == 'rag_json':
        if 'analysis_df_rag' not in session:
            flash('No RAG-enhanced results available', 'error')
            return redirect(url_for('main.results'))

        df = pd.DataFrame(session.get('analysis_df_rag', []))
        json_str = df.to_json(orient='records', indent=2)

        return send_file(
            BytesIO(json_str.encode()),
            mimetype='application/json',
            as_attachment=True,
            download_name=f"threat_analysis_rag_{session.get('selected_model', 'unknown')}.json"
        )

    elif format_type == 'rag_csv':
        if 'analysis_df_rag' not in session:
            flash('No RAG-enhanced results available', 'error')
            return redirect(url_for('main.results'))

        df = pd.DataFrame(session.get('analysis_df_rag', []))
        csv_str = df.to_csv(index=False)

        return send_file(
            BytesIO(csv_str.encode()),
            mimetype='text/csv',
            as_attachment=True,
            download_name=f"threat_analysis_rag_{session.get('selected_model', 'unknown')}.csv"
        )

    elif format_type == 'comparison_csv':
        # Get diagram index and model name to construct comparison key
        diagram_index = session.get('selected_diagram_index', 0)
        model_name = session.get('selected_model', 'unknown')
        comparison_key = session.get('comparison_last_key', '')

        if comparison_key not in session:
            flash('No comparison data available', 'error')
            return redirect(url_for('main.compare'))

        df = pd.DataFrame(session.get(comparison_key, []))

        if df.empty:
            flash('No comparison data available', 'error')
            return redirect(url_for('main.compare'))

        csv_str = df.to_csv(index=False, sep='\t')

        return send_file(
            BytesIO(csv_str.encode()),
            mimetype='text/csv',
            as_attachment=True,
            download_name=f"threat_comparison_{model_name}_{diagram_index}.csv"
        )

    elif format_type == 'coverage_csv':
        if not session.get('coverage_runs'):
            flash('No coverage data available', 'error')
            return redirect(url_for('main.coverage'))

        runs = session.get('coverage_runs', {})
        last = session.get('coverage_last')
        df = pd.DataFrame(runs.get(last, {}).get('rows', []))
        csv_str = df.to_csv(index=False, sep='	')

        return send_file(
            BytesIO(csv_str.encode()),
            mimetype='text/csv',
            as_attachment=True,
            download_name=f"threat_coverage_{session.get('selected_model', 'unknown')}.csv"
        )

    flash('Invalid download format', 'error')
    return redirect(url_for('main.results'))

