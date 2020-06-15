package k8s

import (
	"fmt"
	"encoding/json"
	"regexp"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// ValidateApPolicy validates Policy resource
func ValidateApPolicy(policy *unstructured.Unstructured) error {
	polName := policy.GetName()
	spec, found, err := unstructured.NestedMap(policy.Object, "spec")
	if err != nil {
		return fmt.Errorf("Could not get spec from App Protect Policy %v: %v", polName, err)
	}
	
	if !found {
		return fmt.Errorf("'spec' field not found in App Protect Policy %v", polName)
	}
	
	_ , err = json.Marshal(spec)
	if err != nil {
		return fmt.Errorf("Could not decode App Protect Policy %v: %v ", polName , err)
	}

	return nil
}

// ValidateApLogConf validates LogConfiguration resource 
func ValidateApLogConf(logConf *unstructured.Unstructured) error {
	lcName := logConf.GetName()
	spec, found, err := unstructured.NestedMap(logConf.Object, "spec")
	if err != nil {
		return fmt.Errorf("Could not get spec from App Protect LogConfiguration %v: %v", lcName, err)
	}
	
	if !found {
		return fmt.Errorf("'spec' field not found in App LogConfiguration %v", lcName)
	}
	
	_ , err = json.Marshal(spec)
	if err != nil {
		return fmt.Errorf("Could not decode App Protect LogConfiguration %v: %v ", lcName , err)
	}

	return nil
}

var logDstEx = regexp.MustCompile(`syslog:server=(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}`)

//ValidateApLogConfAnnotation validates annotation for log configuration
func ValidateApLogConfAnnotations(antn string, dstAntn string) (lcns string, lcn string, lcdst string, err error) {
	errormsg := "Error parsing App Protect Log config: Destination Annotation must follow format: syslog:server=<ip-address>:<port>"
	lcdst = dstAntn
	if ! logDstEx.MatchString(lcdst) {
		return "", "", "", fmt.Errorf("%s Log Destinatin did not match regex",errormsg)
	}
	
	lcns, lcn, err = ParseNamespaceName(antn)
	if err != nil {
		return "", "", "", err
	}
	return lcns, lcn, lcdst, nil
}