package burp;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class BurpExtender implements IBurpExtender, IScannerCheck
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    // test / grep strings
    private static final byte[] GREP_STRING = "(href=\"|src=\"|location: )?(?<url>(https?|ftp|file)://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|])".getBytes();
    private static final byte[] INJ_TEST = "|".getBytes();
    private static final byte[] INJ_ERROR = "Unexpected pipe".getBytes();
    private String strresp = "";
    private List<String> matchlist = new ArrayList<String>();
    //
    // implement IBurpExtender
    //
    
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;
        
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        
        // set our extension name
        callbacks.setExtensionName("URL Buster");
        
        // register ourselves as a custom scanner check
        callbacks.registerScannerCheck(this);
        

    }
    
    // helper method to search a response for occurrences of a literal match string
    // and return a list of start/end offsets
    private List<int[]> getMatches(byte[] response, byte[] match)
    {
    	List<int[]> matches = new ArrayList<int[]>();
        
        strresp = helpers.bytesToString(response);
        Pattern patt = Pattern.compile(helpers.bytesToString(match));
        Matcher matcher = patt.matcher(strresp);
        
        int start = 0;
        while (start < helpers.bytesToString(response).length())
        {
            try
            {
            matcher.find(start);
        	String singlematch = matcher.group("url");
        	int found = 0;
        	for (int i = 0; i < matchlist.size(); i++)
        	{
        		if (matchlist.get(i).equals(singlematch))
        			{
        			found = 1;
        			}
        	}
        	if (found == 0)
        	{
        		matchlist.add(singlematch);
        		matches.add(new int[] { matcher.start(), matcher.end() });
        	}
        	start = matcher.end();
            }
            catch (IllegalStateException e)
            	{
            	break;
            	}
        }
        return matches;
    }

    //
    // implement IScannerCheck
    // 
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse)
    {
        // look for matches of our passive check grep string
        List<int[]> matches = getMatches(baseRequestResponse.getResponse(), GREP_STRING);
        if (matches.size() > 0)
        {
            // report the issue
            List<IScanIssue> issues = new ArrayList<>(1);
            String results = "<br>";
            for (int i = 0; i < matchlist.size(); i++)
            {
            	results += matchlist.get(i) + "<br>";
            }
            issues.add(new CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    helpers.analyzeRequest(baseRequestResponse).getUrl(), 
                    new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, matches) }, 
                    "Links Found",
                    "The response contains the following links: " + results,
                    "Information"));
            return issues;
        }
        else return null;
    }

    
    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint)
    {
        /*
    	// make a request containing our injection test in the insertion point
        byte[] checkRequest = insertionPoint.buildRequest(INJ_TEST);
        IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), checkRequest);

        // look for matches of our active check grep string
        List<int[]> matches = getMatches(checkRequestResponse.getResponse(), INJ_ERROR);
        if (matches.size() > 0)
        {
            // get the offsets of the payload within the request, for in-UI highlighting
            List<int[]> requestHighlights = new ArrayList<>(1);
            requestHighlights.add(insertionPoint.getPayloadOffsets(INJ_TEST));

            // report the issue
            List<IScanIssue> issues = new ArrayList<>(1);
            issues.add(new CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    helpers.analyzeRequest(baseRequestResponse).getUrl(), 
                    new IHttpRequestResponse[] { callbacks.applyMarkers(checkRequestResponse, requestHighlights, matches) }, 
                    "Pipe injection",
                    "Submitting a pipe character returned the string: " + helpers.bytesToString(INJ_ERROR),
                    "High"));
            return issues;
        }
        else return null;
        */
    	return this.doActiveScan(baseRequestResponse, insertionPoint);
    }
    
    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue)
    {
        // This method is called when multiple issues are reported for the same URL 
        // path by the same extension-provided check. The value we return from this 
        // method determines how/whether Burp consolidates the multiple issues
        // to prevent duplication
        //
        // Since the issue name is sufficient to identify our issues as different,
        // if both issues have the same name, only report the existing issue
        // otherwise report both issues
        if (existingIssue.getIssueName().equals(newIssue.getIssueName()))
            return -1;
        else return 0;
    }
}

//
// class implementing IScanIssue to hold our custom scan issue details
//
class CustomScanIssue implements IScanIssue
{
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String detail;
    private String severity;

    public CustomScanIssue(
            IHttpService httpService,
            URL url, 
            IHttpRequestResponse[] httpMessages, 
            String name,
            String detail,
            String severity)
    {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.detail = detail;
        this.severity = severity;
    }
    
    @Override
    public URL getUrl()
    {
        return url;
    }

    @Override
    public String getIssueName()
    {
        return name;
    }

    @Override
    public int getIssueType()
    {
        return 0;
    }

    @Override
    public String getSeverity()
    {
        return severity;
    }

    @Override
    public String getConfidence()
    {
        return "Certain";
    }

    @Override
    public String getIssueBackground()
    {
        return null;
    }

    @Override
    public String getRemediationBackground()
    {
        return null;
    }

    @Override
    public String getIssueDetail()
    {
        return detail;
    }

    @Override
    public String getRemediationDetail()
    {
        return null;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages()
    {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService()
    {
        return httpService;
    }
    
}
