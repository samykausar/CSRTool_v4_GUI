package com.francetelecom.csrtool.gui.authent.gassi;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.Principal;
import java.util.Enumeration;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.UnavailableException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.collections.IteratorUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;

import com.francetelecom.csrtool.model.logging.FuncLogging;
import com.francetelecom.csrtool.utils.CSRToolUtil;

/**
 * A servlet filter that simulate the GASSI by adding the same GASSI headers to
 * requests. Informations about users are read from a flat properties file.
 * 
 * @author Team India
 * @version G0RxxCxx
 */
public class GassiMockFilter implements Filter {

	/** Logger **/
	private static Logger logger = Logger.getLogger(GassiMockFilter.class);
	
	/** properties file name **/
	private static final String PROP_FILENAME = "propertiesfile";
	
	/** properties app roles**/
	private static final String PROP_USE_APP_ROLES = "useApplicationRolesInsteadOfUserCredentials";
	
	/** gassi prefix **/
	private static final String PROP_GASSIPREFIX = "gassiprefix";

	/** properties file name **/
	private String propertiesFileName;
	
	/** flag for application roles rather than user credentials **/
	private boolean useApplicationRolesInsteadOfUserCredentials = true;
	
	/** gassi database **/
	private Properties gassiDB;
	
	/** gassi prefix string **/
	private String gassiPrefixString;

	/**
	 * Initilizes the filter
	 * <BR>Callback method; It is called when filter initialized.
	 * 
	 * @param config Filter configuration object
	 * @throws ServletException general exception a servlet can throw when it encounters difficulty
	 */
	public void init(FilterConfig config) throws ServletException {
		try {
			propertiesFileName = StringUtils.trimToNull(config.getInitParameter(PROP_FILENAME));
			if (propertiesFileName == null) {
				throw new ServletException(String.format("missing init parameter: %s", PROP_FILENAME));
			}

			gassiPrefixString = StringUtils.trimToNull(config.getInitParameter(PROP_GASSIPREFIX));
			if (gassiPrefixString == null) {
				throw new ServletException(String.format("missing init parameter: %s", PROP_GASSIPREFIX));
			}

			String str = StringUtils.trimToNull(config.getInitParameter(PROP_USE_APP_ROLES));
			if (str != null) {
				useApplicationRolesInsteadOfUserCredentials = Boolean.parseBoolean(str);
			} else {
				if(logger.isInfoEnabled()) {
					logger.info(FuncLogging.getLogFormatedMessage("GassiMockFilter","init", FuncLogging.REQUEST_STATUS_FAILED, 
						null, String.format("missing init parameter: %s, default value %b used", PROP_USE_APP_ROLES, useApplicationRolesInsteadOfUserCredentials)));
				}
			}

			/*
			 * Load the Gassi DB from the file
			 */
			gassiDB = loadGassiDB();

		} catch (IOException e) {
			UnavailableException unavailableException = new UnavailableException("initialization failure");
			logger.error(FuncLogging.getLogFormatedMessage("GassiMockFilter","init",
						 FuncLogging.REQUEST_STATUS_FAILED, null,e.getMessage()), e);
			unavailableException.initCause(e);
			throw unavailableException;
		}
	}

	/**
	 * Load the Gassi DB from the file.
	 * 
	 * @return Properties with values
	 * @throws IOException input output exception
	 */
	private Properties loadGassiDB() throws IOException {		
		if (logger.isDebugEnabled()) {		
			logger.debug(FuncLogging.getLogFormatedMessage("GassiMockFilter","loadGassiDB",
				String.valueOf(FuncLogging.REQUEST_STATUS_SUCCESS), null,String.format("loading GASSI mock data from: %s", propertiesFileName)));
		}
		InputStream gassiDBInputStream = this.getClass().getResourceAsStream(propertiesFileName);
		if (gassiDBInputStream == null) {
			throw new FileNotFoundException(propertiesFileName);
		}

		Properties gassiDB = new Properties();
		gassiDB.load(gassiDBInputStream);
		return gassiDB;
	}

	/**
	 * Finalize the filter
	 * <BR>Callback method; It is called just before filter destroys.
	 */
	public void destroy() {
		// do nothing
	}

	/**
	 * Main filter logic implementation
	 * <BR>Callback method; It is called for each request.
	 * @param request servlet request object
	 * @param response servlet response object
	 * @param chain filter chain object
	 * @throws IOException input output exception
	 * @throws ServletException general exception a servlet can throw when it encounters difficulty
	 */
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
		if (!(request instanceof HttpServletRequest)) {
			chain.doFilter(request, response);
			return;
		}

		HttpServletRequest httpRequest = (HttpServletRequest) request;
		HttpServletResponse httpResponse = (HttpServletResponse) response;

		Principal userPrincipal = httpRequest.getUserPrincipal();
		if (userPrincipal == null) {
			// User not authenticated
			httpResponse.sendError(401); /* Unauthorized */
			return;
		}

		String userLogin = userPrincipal.getName();
		String[] userInfos = readUserInfos(userLogin);

		/* 
		 * Notice that HttpRequest is immutable that's why we need a wrapped HttpRequest. 
		 */
		GassiMockRequestWrapper gassiMockRequestWrapper = 
			new GassiMockRequestWrapper(httpRequest, userInfos, gassiPrefixString, useApplicationRolesInsteadOfUserCredentials);

		/* 
		 * Continue the filter-chain substituting our RequestWrapper to the original HTTP request 
		 */
		chain.doFilter(gassiMockRequestWrapper, response);
	}

	/**
	 * Reads the gassi information for one user.
	 * @param userName user name
	 * @return an array of String.
	 * @throws IOException input output exception
	 */
	private String[] readUserInfos(String userName) throws IOException {
		String userInfos = gassiDB.getProperty(userName);
		if (userInfos == null) {
			throw new IOException(String.format("username \"%s\" not defined in file: %s", userName, propertiesFileName));
		}

		/* 
		 * Concatenate the username at the begining of the string then split on each ';'
		 */
		return String.format("%s;%s", userName, userInfos).split(";");
	}
}

/**
 * A wrapper around the HttpRequest. 
 * <BR>Since the HttpRequest is immutable we can't realy add our header into the request. 
 * <BR>Instead, the wrapper intercepts calls to getHeader() and if the asked header match one of the GASSI header then the
 * wrapper returns the expected value on the fly.
 * 
 * @class GassiMockRequestWrapper
 * @extends HttpServletRequestWrapper
 */
class GassiMockRequestWrapper extends HttpServletRequestWrapper {
	/**
	 * gassiHeaders map 
	 * **/
	private Map<String, String> gassiHeaders = new TreeMap<String, String>();

	/**
	 * Constructor (parameterized)
	 * 
	 * @param request HTTP request
	 * @param userInfos User information
	 * @param gassiPrefix Gassi prefix
	 * @param useApplicationRolesInsteadOfUserCredentials Whether to use roles instead of User credentials
	 */
	public GassiMockRequestWrapper(HttpServletRequest request, String[] userInfos, String gassiPrefix, boolean useApplicationRolesInsteadOfUserCredentials) {
		super(request);

		/*
		 * trim to null to simulate the absence of the header in case the value is not provided
		 */
		String sm_universalid = StringUtils.trimToNull(userInfos[0]);
		String ftusergivenname = StringUtils.trimToNull(userInfos[1]);
		String ftusersn = StringUtils.trimToNull(userInfos[2]);
		String mcoName = StringUtils.trimToNull(userInfos[3]);
		String adminRoleName = StringUtils.trimToNull(userInfos[4]);
		String userRoleName = StringUtils.trimToNull(userInfos[5]);

		if (sm_universalid != null) {
			gassiHeaders.put("sm_universalid", sm_universalid);
		}

		if (ftusergivenname != null) {
			gassiHeaders.put("ftusergivenname", ftusergivenname);
		}

		if (ftusersn != null) {
			gassiHeaders.put("ftusersn", ftusersn);
		}

		if (useApplicationRolesInsteadOfUserCredentials) {
			/*
			 * Put the MCO into the ftusercredentials
			 */
			if (mcoName != null) {
				gassiHeaders.put("ftusercredentials", String.format("%s %s", gassiPrefix, mcoName));
			}

			if (CSRToolUtil.isNotNull(adminRoleName) && CSRToolUtil.isNotNull(userRoleName)) {
				/*
				 * Put both roles into the ftapplicationroles as a comma
				 * separated list
				 */
				gassiHeaders.put("ftapplicationroles", String.format("%s %s,%1$s %s", gassiPrefix, adminRoleName, userRoleName));
			} else {
				/*
				 * Put the single role into the ftapplicationroles
				 */
				gassiHeaders.put("ftapplicationroles", String.format("%s %s", gassiPrefix, (CSRToolUtil.isNotNull(adminRoleName)) ? adminRoleName : userRoleName));
			}

		} else {
			/*
			 * Put the MCO and the roles, into the ftusercredentials separated by ';'
			 */
			gassiHeaders.put("ftusercredentials", String.format("%s %s;%s;%s", gassiPrefix, mcoName, adminRoleName, userRoleName));
		}
	}

	
	/**
	 * @param name header name
	 * @return gassi header name 
	 * **/
	@Override
	public String getHeader(String name) {
		if(gassiHeaders.containsKey(name)) {
			return gassiHeaders.get(name);
		} else {
			return  super.getHeader(name);
		}
	}

	/**
	 * @return  enumeration of gassi header
	 * **/
	@Override
	public Enumeration<String> getHeaderNames() {
		return IteratorUtils.asEnumeration(IteratorUtils.chainedIterator(gassiHeaders.keySet().iterator(), IteratorUtils.asIterator(super.getHeaderNames())));
	}
}
