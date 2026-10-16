import java.io.File;
import java.util.ArrayList;
import java.util.List;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/** Offline Maven dependency inventory. XML external entities are disabled. */
public final class NoxtracePomAudit {
    private static String child(Element element, String name) {
        NodeList list = element.getElementsByTagNameNS("*", name);
        if (list.getLength() == 0) return "";
        Node node = list.item(0);
        return node.getTextContent() == null ? "" : node.getTextContent().trim();
    }
    private static String clean(String value) { return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n").replace("\r", "\\r"); }
    public static void main(String[] args) {
        if (args.length != 1) { System.err.println("Usage: java NoxtracePomAudit.java pom.xml"); System.exit(2); }
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            Element root = factory.newDocumentBuilder().parse(new File(args[0])).getDocumentElement();
            NodeList all = root.getElementsByTagNameNS("*", "dependency");
            List<String> rows = new ArrayList<>();
            for (int i=0; i<all.getLength(); i++) {
                Node node = all.item(i);
                if (!(node instanceof Element)) continue;
                Element dep = (Element) node;
                String group = child(dep, "groupId"), artifact = child(dep, "artifactId"), version = child(dep, "version");
                if (group.isEmpty() && artifact.isEmpty()) continue;
                boolean review = version.isEmpty() || version.toUpperCase().contains("SNAPSHOT") || version.equalsIgnoreCase("LATEST") || version.equalsIgnoreCase("RELEASE") || version.startsWith("[") || version.startsWith("(");
                rows.add("    {\"group_id\":\"" + clean(group) + "\",\"artifact_id\":\"" + clean(artifact) + "\",\"version\":\"" + clean(version) + "\",\"needs_review\":" + review + "}");
            }
            System.out.println("{\n  \"engine\": \"Java/Maven offline inventory\",\n  \"file\": \"" + clean(args[0]) + "\",\n  \"dependency_count\": " + rows.size() + ",\n  \"network_queries_performed\": false,\n  \"dependencies\": [" + String.join(",\n", rows) + "]\n}");
            System.err.println("Review hints are not CVE findings. Check dependencyManagement and your trusted vulnerability advisory source.");
        } catch (Exception ex) {
            System.err.println("NOXTRACE Java engine failed: " + ex.getClass().getSimpleName() + ": " + ex.getMessage());
            System.exit(1);
        }
    }
}
