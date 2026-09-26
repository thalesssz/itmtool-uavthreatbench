"""Parser for .tm7 files"""
import xml.etree.ElementTree as ET
from typing import List, Dict, Optional
import json
import pandas as pd

from .threat_model import (
    ThreatModelTM7,
    DiagramTM7,
    ElementTM7,
    DataFlowTM7,
    TrustBoundaryTM7,
    ThreatTM7,
    PropertyTM7
)

# XML namespaces used in .tm7 files
NAMESPACES = {
    'tm': 'http://schemas.datacontract.org/2004/07/ThreatModeling.Model',
    'abs': 'http://schemas.datacontract.org/2004/07/ThreatModeling.Model.Abstracts',
    'kb': 'http://schemas.datacontract.org/2004/07/ThreatModeling.KnowledgeBase',
    'i': 'http://www.w3.org/2001/XMLSchema-instance',
    'z': 'http://schemas.microsoft.com/2003/10/Serialization/',
    'a': 'http://schemas.microsoft.com/2003/10/Serialization/Arrays'
}


class TM7Parser:
    """Parser for Microsoft Threat Modeling Tool .tm7 XML files."""

    def __init__(self, xml_content: str):
        """Initialize parser with raw XML string."""
        self.root = ET.fromstring(xml_content)

    def parse(self) -> ThreatModelTM7:
        """Parse the full .tm7 file into a ThreatModelTM7 instance."""
        model = ThreatModelTM7(version=self._get_version())
        
        # Parse diagramas
        model.diagrams = self._parse_diagrams()
        
        # Parse ameaças
        model.threats = self._parse_threats()
        
        # Parse meta informações
        model.meta_info = self._parse_meta_info()
        
        return model
    
    def _get_version(self) -> str:
        """Return the threat model version from the XML root."""
        version_elem = self.root.find('.//tm:Version', NAMESPACES)
        return version_elem.text if version_elem is not None else "Unknown"
    
    def _parse_diagrams(self) -> List[DiagramTM7]:
        """Parse all diagrams from DrawingSurfaceList."""
        diagrams = []
        drawing_surfaces = self.root.findall('.//tm:DrawingSurfaceList/tm:DrawingSurfaceModel', NAMESPACES)
        
        for surface in drawing_surfaces:
            diagram = self._parse_diagram(surface)
            diagrams.append(diagram)
        
        return diagrams
    
    def _parse_diagram(self, surface_elem) -> DiagramTM7:
        """Parse a single diagram (elements, data flows, trust boundaries)."""
        guid = self._get_text(surface_elem, './/abs:Guid', NAMESPACES)
        name = self._get_property_value(surface_elem, 'Name')
        
        diagram = DiagramTM7(guid=guid, name=name)
        
        # Parse elementos (Process, External Interactor, Data Store)
        borders = surface_elem.find('.//tm:Borders', NAMESPACES)
        if borders is not None:
            for kv_pair in borders.findall('.//a:KeyValueOfguidanyType', NAMESPACES):
                element = self._parse_element(kv_pair)
                if element:
                    if element.generic_type_id == 'GE.TB.B':
                        # É uma Trust Boundary
                        tb = TrustBoundaryTM7(
                            guid=element.guid,
                            name=element.name,
                            left=element.left,
                            top=element.top,
                            width=element.width,
                            height=element.height
                        )
                        diagram.trust_boundaries.append(tb)
                    else:
                        diagram.elements.append(element)
        
        # Parse dataflows
        lines = surface_elem.find('.//tm:Lines', NAMESPACES)
        if lines is not None:
            for kv_pair in lines.findall('.//a:KeyValueOfguidanyType', NAMESPACES):
                dataflow = self._parse_dataflow(kv_pair)
                if dataflow:
                    diagram.dataflows.append(dataflow)
        
        # Detectar quais boundaries cada dataflow cruza
        self._detect_boundary_crossings(diagram)
        
        return diagram
    
    def _parse_element(self, kv_elem) -> Optional[ElementTM7]:
        """Parse a single element (Process, External Interactor, Data Store, etc.)."""
        value_elem = kv_elem.find('.//a:Value', NAMESPACES)
        if value_elem is None:
            return None
        
        guid = self._get_text(value_elem, './/abs:Guid', NAMESPACES)
        type_id = self._get_text(value_elem, './/abs:TypeId', NAMESPACES)
        generic_type_id = self._get_text(value_elem, './/abs:GenericTypeId', NAMESPACES)
        name = self._get_property_value(value_elem, 'Name')
        
        # Propriedades de posição
        left = self._get_float(value_elem, './/abs:Left', NAMESPACES)
        top = self._get_float(value_elem, './/abs:Top', NAMESPACES)
        width = self._get_float(value_elem, './/abs:Width', NAMESPACES)
        height = self._get_float(value_elem, './/abs:Height', NAMESPACES)
        
        properties = self._parse_properties(value_elem)
        
        return ElementTM7(
            guid=guid,
            type_id=type_id,
            generic_type_id=generic_type_id,
            name=name,
            properties=properties,
            left=left,
            top=top,
            width=width,
            height=height
        )
    
    def _parse_dataflow(self, kv_elem) -> Optional[DataFlowTM7]:
        """Parse a single data flow between two elements."""
        value_elem = kv_elem.find('.//a:Value', NAMESPACES)
        if value_elem is None:
            return None
        
        guid = self._get_text(value_elem, './/abs:Guid', NAMESPACES)
        name = self._get_property_value(value_elem, 'Name')
        source_guid = self._get_text(value_elem, './/abs:SourceGuid', NAMESPACES)
        target_guid = self._get_text(value_elem, './/abs:TargetGuid', NAMESPACES)
        
        properties = self._parse_properties(value_elem)
        
        return DataFlowTM7(
            guid=guid,
            name=name,
            source_guid=source_guid,
            target_guid=target_guid,
            properties=properties
        )
    
    def _parse_properties(self, elem) -> List[PropertyTM7]:
        """Parse properties of an element (name, value, list options)."""
        properties = []
        props_elem = elem.find('.//abs:Properties', NAMESPACES)
        
        if props_elem is None:
            return properties
        
        for any_type in props_elem.findall('.//a:anyType', NAMESPACES):
            prop_type = any_type.get('{http://www.w3.org/2001/XMLSchema-instance}type', '')
            
            display_name = self._get_text(any_type, './/kb:DisplayName', NAMESPACES)
            name = self._get_text(any_type, './/kb:Name', NAMESPACES)
            value = self._get_text(any_type, './/kb:Value', NAMESPACES)
            
            # Parse lista de valores para ListDisplayAttribute
            values = []
            selected_index = None
            if 'ListDisplayAttribute' in prop_type:
                value_array = any_type.find('.//kb:Value', NAMESPACES)
                if value_array is not None:
                    for string_val in value_array.findall('.//a:string', NAMESPACES):
                        if string_val.text:
                            values.append(string_val.text)
                
                selected_idx_elem = any_type.find('.//kb:SelectedIndex', NAMESPACES)
                if selected_idx_elem is not None:
                    selected_index = int(selected_idx_elem.text)
            
            prop = PropertyTM7(
                display_name=display_name or '',
                name=name,
                value=value,
                selected_index=selected_index,
                values=values
            )
            properties.append(prop)
        
        return properties
    
    def _parse_threats(self) -> List[ThreatTM7]:
        """Parse all threat instances from the model."""
        threats = []
        threat_instances = self.root.find('.//tm:ThreatInstances', NAMESPACES)
        
        if threat_instances is None:
            return threats
        
        for kv_pair in threat_instances.findall('.//a:KeyValueOfstringThreatpc_P0_PhOB', NAMESPACES):
            threat = self._parse_threat(kv_pair)
            if threat:
                threats.append(threat)
        
        return threats
    
    def _parse_threat(self, kv_elem) -> Optional[ThreatTM7]:
        """Parse a single threat instance."""
        value_elem = kv_elem.find('.//a:Value', NAMESPACES)
        if value_elem is None:
            return None
        
        threat_id = self._get_text(kv_elem, './/a:Key', NAMESPACES)
        type_id = self._get_text(value_elem, './/kb:TypeId', NAMESPACES)
        priority = self._get_text(value_elem, './/kb:Priority', NAMESPACES)
        state = self._get_text(value_elem, './/kb:State', NAMESPACES)
        source_guid = self._get_text(value_elem, './/kb:SourceGuid', NAMESPACES)
        target_guid = self._get_text(value_elem, './/kb:TargetGuid', NAMESPACES)
        flow_guid = self._get_text(value_elem, './/kb:FlowGuid', NAMESPACES)
        
        # Parse propriedades da ameaça
        props = value_elem.find('.//kb:Properties', NAMESPACES)
        title = ""
        category = ""
        description = ""
        
        if props is not None:
            for kv in props.findall('.//a:KeyValueOfstringstring', NAMESPACES):
                key = self._get_text(kv, './/a:Key', NAMESPACES)
                val = self._get_text(kv, './/a:Value', NAMESPACES)
                
                if key == 'Title':
                    title = val
                elif key == 'UserThreatCategory':
                    category = val
                elif key == 'UserThreatDescription':
                    description = val
        
        return ThreatTM7(
            threat_id=threat_id,
            type_id=type_id,
            title=title,
            category=category,
            description=description,
            priority=priority,
            state=state,
            source_guid=source_guid,
            target_guid=target_guid,
            flow_guid=flow_guid
        )
    
    def _parse_meta_info(self) -> Dict[str, str]:
        """Parse meta information (key-value pairs) from the model."""
        meta_info = {}
        meta_elem = self.root.find('.//tm:MetaInformation', NAMESPACES)
        
        if meta_elem is not None:
            for child in meta_elem:
                tag = child.tag.split('}')[-1]  # Remove namespace
                meta_info[tag] = child.text or ""
        
        return meta_info
    
    def _get_property_value(self, elem, prop_name: str) -> str:
        """Return the value of a property by name (or DisplayName)."""
        props_elem = elem.find('.//abs:Properties', NAMESPACES)
        if props_elem is None:
            return ""
        
        for any_type in props_elem.findall('.//a:anyType', NAMESPACES):
            name = self._get_text(any_type, './/kb:Name', NAMESPACES)
            display_name = self._get_text(any_type, './/kb:DisplayName', NAMESPACES)
            
            # Match by Name or DisplayName
            if name == prop_name or display_name == prop_name:
                value = self._get_text(any_type, './/kb:Value', NAMESPACES)
                if value:
                    return value
        
        return ""
    
    def _get_text(self, elem, xpath: str, namespaces: dict) -> str:
        """Return text content of the first element matching xpath, or empty string."""
        found = elem.find(xpath, namespaces)
        return found.text if found is not None and found.text else ""
    
    def _get_float(self, elem, xpath: str, namespaces: dict) -> Optional[float]:
        """Return float value of the first element matching xpath, or None."""
        text = self._get_text(elem, xpath, namespaces)
        try:
            return float(text) if text else None
        except ValueError:
            return None
    
    def _detect_boundary_crossings(self, diagram: DiagramTM7) -> None:
        """Detect which trust boundaries each data flow crosses and set crossed_boundaries."""
        # Criar mapa de elementos por GUID
        elements_map = {elem.guid: elem for elem in diagram.elements}
        
        for dataflow in diagram.dataflows:
            # Obter posições dos elementos source e target
            source_elem = elements_map.get(dataflow.source_guid)
            target_elem = elements_map.get(dataflow.target_guid)
            
            if not source_elem or not target_elem:
                continue
            
            # Calcular centro dos elementos
            source_center = self._get_element_center(source_elem)
            target_center = self._get_element_center(target_elem)
            
            # Verificar quais boundaries são cruzadas
            for boundary in diagram.trust_boundaries:
                if self._line_crosses_boundary(source_center, target_center, boundary):
                    dataflow.crossed_boundaries.append(boundary.guid)
    
    def _get_element_center(self, element: ElementTM7) -> tuple:
        """Return (center_x, center_y) of the element's bounding box."""
        if element.left is None or element.top is None:
            return (0, 0)
        
        center_x = element.left + (element.width or 0) / 2
        center_y = element.top + (element.height or 0) / 2
        return (center_x, center_y)
    
    def _line_crosses_boundary(self, p1: tuple, p2: tuple, boundary: TrustBoundaryTM7) -> bool:
        """
        Return True if the line between p1 and p2 crosses the trust boundary
        (one point inside, one outside the boundary rectangle).
        """
        p1_inside = self._point_inside_boundary(p1, boundary)
        p2_inside = self._point_inside_boundary(p2, boundary)
        
        # Cruza se um está dentro e outro fora
        return p1_inside != p2_inside
    
    def _point_inside_boundary(self, point: tuple, boundary: TrustBoundaryTM7) -> bool:
        """Return True if the point (x, y) is inside the boundary rectangle."""
        x, y = point
        
        return (boundary.left <= x <= boundary.left + boundary.width and
                boundary.top <= y <= boundary.top + boundary.height)


def dataflows_to_json(diagram: DiagramTM7, create_file: bool = False) -> List[Dict]:
    """
    Convert diagram data flows to a list of JSON-serializable dictionaries.

    Each entry includes id, source, target, data_flow name, and trust_boundaries
    crossed by that flow.

    Args:
        diagram: Diagram containing dataflows, elements, and trust_boundaries.
        create_file: If True, write the result to a JSON file (dataflow_<name>.json).

    Returns:
        List of dicts with keys: id, source, target, data_flow, trust_boundaries.
    """
    result = []
    
    # Criar um mapa de guid -> elemento para acesso rápido
    elements_map = {}
    for element in diagram.elements:
        elements_map[element.guid] = element
    
    # Criar um mapa de guid -> trust_boundary para acesso rápido
    boundaries_map = {}
    for tb in diagram.trust_boundaries:
        boundaries_map[tb.guid] = tb
    
    # Processar cada dataflow
    for idx, flow in enumerate(diagram.dataflows, start=1):
        # Buscar elementos de origem e destino
        source_element = elements_map.get(flow.source_guid)
        target_element = elements_map.get(flow.target_guid)
        
        # Criar o dicionário do dataflow
        dataflow_dict = {
            "id": f"DFD-{idx:03d}",
            "source": f"{source_element.name} - ({source_element.type_id})" if source_element else f"Unknown ({flow.source_guid})",
            "target": f"{target_element.name} - ({target_element.type_id})" if target_element else f"Unknown ({flow.target_guid})",
            "data_flow": flow.name,
            "trust_boundaries": {},
        }
        
        # Adicionar trust boundaries se existirem
        if flow.crossed_boundaries:
            trust_boundaries = {}
            for boundary_idx, boundary_guid in enumerate(flow.crossed_boundaries, start=1):
                boundary = boundaries_map.get(boundary_guid)
                if boundary:
                    trust_boundaries[boundary_idx] = boundary.name
            
            dataflow_dict["trust_boundaries"] = trust_boundaries
        
        result.append(dataflow_dict)
    
    if create_file:
        filename = f"dataflow_{diagram.name}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
    
    return result


def threat_model_to_json(threat_model: ThreatModelTM7) -> str:
    """
    Convert a threat model to a JSON string with a single "threat_model" key
    containing a list of threat entries (Category, Description, DataFlow).

    Args:
        threat_model: ThreatModelTM7 instance with a non-empty threats list.

    The "DataFlow" value is the flow NAME, not its GUID. ComparisonService pairs
    TMT threats with AI threats using the key (dataflow_name, category), and the
    AI side supplies the flow name. Emitting a GUID here made every key mismatch,
    so no pair was ever compared and every threat was reported as TMT-only or
    AI-only. Falls back to the GUID when the flow cannot be resolved.

    Returns:
        Pretty-printed JSON string (indent=2, ensure_ascii=False).
    """
    threats_data = []

    # Map flow GUID -> flow name across every diagram in the model.
    flow_names = {
        flow.guid: flow.name
        for diagram in threat_model.diagrams
        for flow in diagram.dataflows
    }

    for threat in threat_model.threats:
        threat_entry = {
            "Category": threat.category,
            "Description": threat.description,
            "DataFlow": flow_names.get(threat.flow_guid, threat.flow_guid)
        }
        threats_data.append(threat_entry)

    result = {
        "threat_model": threats_data
    }    

    # Return the JSON string (pretty-printed)
    return json.dumps(result, indent=2, ensure_ascii=False)


def generate_tmt_dataframe(threat_data: str) -> pd.DataFrame:
    """
    Build a pandas DataFrame from threat data (JSON string or dict).

    Expects a top-level "threat_model" key whose value is a list of threat
    objects (e.g. Category, Description, DataFlow).

    Args:
        threat_data: JSON string or already-parsed dict with "threat_model" key.

    Returns:
        DataFrame with one row per threat (columns from threat entries).
    """
    # If it's a JSON string, parse it
    if isinstance(threat_data, str):
        json_data = json.loads(threat_data)
    else:
        json_data = threat_data
    
    # Extract the list inside 'threat_model'
    threat_list = json_data.get("threat_model", [])
    
    # Convert to DataFrame
    df = pd.DataFrame(threat_list)
    
    return df

