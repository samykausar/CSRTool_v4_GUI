package com.francetelecom.csrtool.gui.authent;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.MissingResourceException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.apache.log4j.MDC;
import org.ow2.opensuit.core.util.BeanUtils;
import org.ow2.opensuit.xml.base.enums.Scope;

import com.francetelecom.csrtool.gui.utils.MessagesUtil;
import com.francetelecom.csrtool.model.logging.FuncLogging;
import com.francetelecom.csrtool.model.profiles.CSRPermission;
import com.francetelecom.csrtool.model.profiles.CSRRole;
import com.francetelecom.csrtool.model.profiles.CSRUser;
import com.francetelecom.csrtool.model.profiles.CSRUserInfo;
import com.francetelecom.csrtool.model.profiles.ProfilesException;
import com.francetelecom.csrtool.model.profiles.ProfilesRegistry;
import com.francetelecom.csrtool.model.services.McoFacade;
import com.francetelecom.csrtool.utils.CSRToolUtil;

/**
 * The Authentication filter implementation.<br>
 * This Class is used for authentication of user in CSRTool. <br>
 * It acts as a HTTP request filter for incoming requests to CSRTool.
 * @class AuthentFilter
 * @Implements Filter
 */
public class AuthentFilter implements Filter {
	/**	Logger **/
	private static Logger LOGGER = Logger.getLogger(AuthentFilter.class);

	/** authentication error title **/
	private static final String DEFAULT_TITLE_KEY_AUTH_ERROR = "error.csruser.not_authenticated.title";
	
	/** authentication error message **/
	private static final String DEFAULT_MESSAGE_KEY_AUTH_ERROR = "error.csruser.not_authenticated.message";

	/** authentication error title -french **/
	private static final String DEFAULT_TITLE_AUTH_ERROR_FR = "Authentification au CSRTool invalide ";
	
	/** authentication error message -french **/
	private static final String DEFAULT_MESSAGE_AUTH_ERROR_FR = "Avertissement ! quiconque accéderait ou tenterait d'accéder au SI de Orange sans y être autorisé risque 1 an de prison et 15244 &euro; d'amende (nouveau code penal - article 323-1)";
	
	/** authentication error title -english **/
	private static final String DEFAULT_TITLE_AUTH_ERROR_EN = "Bad authorization to access CSRTool. ";
	
	/** authentication error message -english **/
	private static final String DEFAULT_MESSAGE_AUTH_ERROR_EN = "Warning ! Anyone accessing or attempting to access the IS of Orange without authorization risk 1 year in prison and a fine of &euro; 15,244 (new Penal Code - Article 323-1). ";

	/** authentication parameter error title **/
	private static final String DEFAULT_TITLE_KEY_AUTH_PARAM_ERROR = "error.csruser.invalid_auth_param.title";
	
	/** authentication parameter error message **/
	private static final String DEFAULT_MESSAGE_KEY_AUTH_PARAM_ERROR = "error.csruser.invalid_auth_param.message";
	
	/** authentication parameter error title -french **/
	private static final String DEFAULT_TITLE_AUTH_PARAM_ERROR_FR = "Paramètre d'authentification au CSRTool invalide.";
	
	/** authentication parameter error message -french **/
	private static final String DEFAULT_MESSAGE_AUTH_PARAM_ERROR_FR = "Avertissement ! quiconque accéderait ou tenterait d'accéder au SI de Orange sans y être autorisé risque 1 an de prison et 15244 &euro; d'amende (nouveau code penal - article 323-1)";
	
	/** authentication parameter error title -english **/
	private static final String DEFAULT_TITLE_AUTH_PARAM_ERROR_EN = "Bad authorization parameter to access CSRTool. ";
	
	/** authentication parameter error message -english **/
	private static final String DEFAULT_MESSAGE_AUTH_PARAM_ERROR_EN = "Warning ! Anyone accessing or attempting to access the IS of Orange without authorization risk 1 year in prison and a fine of &euro; 15,244 (new Penal Code - Article 323-1). ";

	/** authentication failure error **/
	private static final String ERROR_AUTHENTICATION_FAILURE = "auth_error";

	/** authentPlugins **/
	private IAuthentPlugin[] authentPlugins;

	/** The collection of extension for resources that do not need authentification. **/
	private Collection<String> bypassedExtensions;

	/**
	 * Initializes the filter
	 * <BR>Callback method; It is called when filter initialized.
	 * @param config Filter configuration object
	 * @throws ServletException general exception a servlet can throw when it encounters difficulty
	 */
	public void init(FilterConfig config) throws ServletException {
		/*
		 * Register the extensions for which authentification is no required.
		 */
		bypassedExtensions = new ArrayList<String>();
		bypassedExtensions.add("js");
		bypassedExtensions.add("gif");
		bypassedExtensions.add("png");

		/*
		 * Make the list of authentication plugins with their initialization.
		 */
		List<IAuthentPlugin> plugins = new ArrayList<IAuthentPlugin>();

		for (int i = 0;; i++) {
			String pluginClassName = config.getInitParameter("plugin." + i);
			if (pluginClassName == null) {
				break;
			}
			try {
				Class<?> c = Class.forName(pluginClassName);

				if (IAuthentPlugin.class.isAssignableFrom(c)) {
					IAuthentPlugin authentPlugin = (IAuthentPlugin) c.newInstance();
					authentPlugin.init(config.getServletContext());
					plugins.add(authentPlugin);
				} else {
					throw new ServletException("plugin." + i + " [" + pluginClassName + "] does not implement IAuthentPlugin");
				}
			} catch (Exception e) {
				LOGGER.error(FuncLogging.getLogFormatedMessage("AuthentFilter","init",
					FuncLogging.REQUEST_STATUS_FAILED, null,e.getMessage()), e);
				throw new ServletException("unable to instanciate plugin." + i + " [" + pluginClassName + "]: ", e);
			}
		}

		if (!plugins.isEmpty()) {
			authentPlugins = new IAuthentPlugin[plugins.size()];
			plugins.toArray(authentPlugins);
		} else {
			if(LOGGER.isInfoEnabled()) {
				LOGGER.info(FuncLogging.getLogFormatedMessage("AuthentFilter","init",
					String.valueOf(FuncLogging.REQUEST_STATUS_FAILED), null,"No authentication plugin initialized"));
			}
			throw new ServletException("No authentication plugin initialized");
		}
	}

	/**
	 * Finalize the filter
	 * <BR>Callback method; It is called just before filter destroys.
	 */
	public void destroy() {
		// Do nothing
	}

	/**
	 * Main filter logic implementation
	 * <BR>Callback method; It is called for each request.
	 * @param request Servlet request
	 * @param response Servlet response
	 * @param chain FilterChain object
	 * @throws ServletException general exception a servlet can throw when it encounters difficulty
	 * @throws IOException input oytput exception
	 */
	@SuppressWarnings("unchecked")
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
		/*
		 * If not an HTTP request, immediately pass on to the next filter.
		 */
		if (!(request instanceof HttpServletRequest)) {
			chain.doFilter(request, response);
			return;
		}
		/*
		 * Downcast the request to its HTTP version.
		 */
		HttpServletRequest httpRequest = (HttpServletRequest) request;
		/*
		 * quickly forward to the next filter if we don't need authentification for the requested
		 * resource.
		 */
		if (bypassAuthent(httpRequest)) {
			chain.doFilter(request, response);
			return;
		}
		/*
		 * Print some debug information. the information is printed only if the request contains a
		 * parameter named 'dumphttp'. The user has to add this parameter to the request by himself
		 * using the location bar of his browser, the value is meaningless.
		 */
		if (httpRequest.getParameter("dumphttp")!=null || LOGGER.isTraceEnabled()) {
			dumpAllHeaders(httpRequest);
		}
		/*
		 * retrieve the (new) authenticated user
		 */
		CSRUser sessionUser = getSessionUser(httpRequest);
		AuthentifiedUser authentifiedUser = getAuthentifiedUser(httpRequest, sessionUser);
		/*
		 * Reject if the user could not be authentified
		 */
		if (authentifiedUser==null && sessionUser==null) {
			dumpAllHeaders(httpRequest);
			printInvalidPage(request, response, DEFAULT_TITLE_KEY_AUTH_ERROR, DEFAULT_MESSAGE_KEY_AUTH_ERROR, ERROR_AUTHENTICATION_FAILURE);
			return;
		}
		/*
		 * Compare the authenticated user to the current user stored in the session.
		 */
		if (CSRToolUtil.isNotNull(authentifiedUser)) {
			try {
				/*
				 * Verify the coherence of the data sent by the GASSI - number of admin and service
				 * role names, presence of the MCO name.
				 */
				authentifiedUser.validate();
				if (LOGGER.isDebugEnabled()) {
					LOGGER.debug(FuncLogging.getLogFormatedMessage("AuthentFilter","doFilter",
							String.valueOf(FuncLogging.REQUEST_STATUS_SUCCESS), null,"validation succeeded for user : " + authentifiedUser.getLogin()));
				}
			} catch (AuthentifiedUser.ValidationException e) {
					LOGGER.error(FuncLogging.getLogFormatedMessage("AuthentFilter","doFilter",
							FuncLogging.REQUEST_STATUS_FAILED, null,e.getMessage()), e);
				dumpAllHeaders(httpRequest);
				printInvalidPage(request, response, DEFAULT_TITLE_KEY_AUTH_ERROR, DEFAULT_MESSAGE_KEY_AUTH_ERROR, ERROR_AUTHENTICATION_FAILURE);
				return;
			}

			try {
				// Tries to check MCO loading provided by user
				McoFacade mcoFacade = McoFacade.get(authentifiedUser.getMco());

				/*
				 * Load the userinfo for the new authentified user from the database.
				 */
				CSRUserInfo userInfo = notifyConnection(authentifiedUser);

				CSRRole userServiceRole = null;
				if (authentifiedUser.getAdminLevel() != CSRPermission.ADMIN_LEVEL && authentifiedUser.getAdminLevel() != CSRPermission.WRITE_LEVEL) {
					/*
					 * Load the roles also
					 */
					userServiceRole = loadRoles(authentifiedUser);
					if (userServiceRole == null) {
						if (LOGGER.isDebugEnabled()) {
							LOGGER.debug(FuncLogging.getLogFormatedMessage("AuthentFilter","doFilter",
							  String.valueOf(FuncLogging.REQUEST_STATUS_FAILED), null,String.format("Role \"%s\" not found in database", authentifiedUser.getServiceRoleName())));
						}
						printInvalidPage(request, response, DEFAULT_TITLE_KEY_AUTH_ERROR, DEFAULT_MESSAGE_KEY_AUTH_ERROR, ERROR_AUTHENTICATION_FAILURE);
						return;
					}
				}

				/*
				 * Create a new CSRUser using the userInfo and the userRoles
				 */
				sessionUser = new CSRUser(userInfo, authentifiedUser.getAdminLevel(), userServiceRole);
			} catch (ProfilesException e) {
					LOGGER.error(FuncLogging.getLogFormatedMessage("AuthentFilter","doFilter",
							FuncLogging.REQUEST_STATUS_FAILED, null,e.getMessage()), e);
				printInvalidPage(request, response, DEFAULT_TITLE_KEY_AUTH_ERROR, DEFAULT_MESSAGE_KEY_AUTH_ERROR, ERROR_AUTHENTICATION_FAILURE);
			}

			if(sessionUser == null) {
				return;
			}
			/*
			 * set this CSRUser as the new current user stored in the session.
			 */
			if(LOGGER.isInfoEnabled()) {
				LOGGER.info(FuncLogging.getLogFormatedMessage("AuthentFilter","doFilter",String.valueOf(FuncLogging.REQUEST_STATUS_SUCCESS), null,"User connected :" + sessionUser.getLogin()));
			}
			setSessionUser(httpRequest, sessionUser);

		}

		try {
			/*
			 * Store the current CSRUser into a thread local for the duration of the request so that
			 * it is always available during the processing of the request.
			 */
			CSRUser.setCurrentCSR(sessionUser);

			// For admin user, the homepage is the ViewAllCSRRoles page
			if (sessionUser.hasAdminLevel(CSRPermission.ADMIN_LEVEL) || sessionUser.hasAdminLevel(CSRPermission.WRITE_LEVEL)) {
				// --- default url: /<ctx_path>/<servlet>
				String[] path = httpRequest.getRequestURI().split("/");
				if (path.length < 4) {
					// This is the default Home page URL
					RequestDispatcher dispatcher = httpRequest.getRequestDispatcher("/Bricks/pg/osuit/pages/csradmin/ViewAllCSRRoles");
					dispatcher.forward(request, response);
					return;
				}
			}
			setLogContext(CSRUser.getCurrentCSR());

			/*
			 * Pass on to the next filter in the chain.
			 */
			chain.doFilter(request, response);
		} finally {
			/*
			 * Remove the current CSRUser from the thread local as a safety mesure.
			 */
			CSRUser.removeCurrentCSR();
		}
	}

	/**
	 * This method is to set the Log context.The keys userInfo and userRole are used in
	 * log4j.properties file to set log pattern.
	 * @param sessionUser CSR User in session
	 **/
	private void setLogContext(CSRUser sessionUser) {
		if (sessionUser != null) {
			MDC.put("userInfo", sessionUser.getUserInfo());
			if(CSRToolUtil.isNull(sessionUser.getRoles())) {
				MDC.put("userRole", new ArrayList<CSRRole>());
			} else {
				MDC.put("userRole", sessionUser.getRoles());
			}
		} else {
			MDC.remove("userInfo");
			MDC.remove("userRole");
		}

	}

	/**
	 * Bypasses the authentication
	 * @param httpRequest HTTP request
	 * @return flag to bypass aunthentication
	 **/
	protected boolean bypassAuthent(HttpServletRequest httpRequest) {
		String uri = httpRequest.getRequestURI();
		if (uri != null) {
			String extension = uri.substring(uri.lastIndexOf('.') + 1);
			return bypassedExtensions.contains(extension);
		}
		return false;
	}

	/**
	 * Display invalid page
	 * @param req servlet request object
	 * @param resp servlet response object
	 * @param titleKey key for the title
	 * @param messageKey key for the message
	 * @param typeOfError error type
	 * @throws ServletException general exception a servlet can throw when it encounters difficulty
	 * @throws IOException input output exception
	 **/
	private void printInvalidPage(ServletRequest req, ServletResponse resp, String titleKey, String messageKey, String typeOfError) throws IOException, ServletException {
		HttpServletResponse response = (HttpServletResponse) resp;

		String titleFr = null, messageFr = null, titleEn = null, messageEn = null;

		if (titleKey != null) {
			try {
				titleFr = MessagesUtil.getMessage(Locale.FRANCE,  titleKey);
				titleEn = MessagesUtil.getMessage(Locale.ENGLISH, titleKey);
			} catch (MissingResourceException e) {
				LOGGER.warn(FuncLogging.getLogFormatedMessage("AuthentFilter","doFilter",
						FuncLogging.REQUEST_STATUS_FAILED, null,e.getMessage()), e);
				if (titleFr == null) {
					if(ERROR_AUTHENTICATION_FAILURE.equals(typeOfError)) {
						titleFr = DEFAULT_TITLE_AUTH_ERROR_FR;
					} else {
						titleFr = DEFAULT_TITLE_AUTH_PARAM_ERROR_FR;
					}
				}

				if (titleEn == null) {
					if(ERROR_AUTHENTICATION_FAILURE.equals(typeOfError)) {
						titleEn = DEFAULT_TITLE_AUTH_ERROR_EN;
					} else {
						titleEn = DEFAULT_TITLE_AUTH_PARAM_ERROR_EN;
					}
				}
			}
		}

		if (CSRToolUtil.isNotNull(messageKey)) {
			try {
				messageFr = MessagesUtil.getMessage(Locale.FRANCE,   messageKey);
				messageEn = MessagesUtil.getMessage(Locale.ENGLISH,  messageKey);
			} catch (MissingResourceException e) {
				LOGGER.warn(FuncLogging.getLogFormatedMessage("AuthentFilter","printInvalidPage",
						FuncLogging.REQUEST_STATUS_FAILED, null,e.getMessage()), e);

				if (messageFr == null) {
					if(ERROR_AUTHENTICATION_FAILURE.equals(typeOfError)) {
						messageFr = DEFAULT_MESSAGE_AUTH_ERROR_FR;
					} else {
						messageFr = DEFAULT_MESSAGE_AUTH_PARAM_ERROR_FR;
					}
				}

				if (messageEn == null) {
					if(ERROR_AUTHENTICATION_FAILURE.equals(typeOfError)) {
						messageEn = DEFAULT_MESSAGE_AUTH_ERROR_EN;
					} else { 
						messageEn = DEFAULT_MESSAGE_AUTH_PARAM_ERROR_EN;
					}
				}
			}
		}

		PrintWriter out = response.getWriter();
		StringBuilder builder = new StringBuilder(1024);
		builder.append("<HEAD><TITLE>CSRTool : Authentication Problem</TITLE></HEAD>");
		builder.append("<BODY><TABLE ALIGN=CENTER VALIGN=CENTER><TR><TH>").append(titleFr).append("</TH></TR>");
		builder.append("<TR><TD><HR><FONT COLOR='red'>").append(messageFr).append("</FONT></HR></TD>");
		builder.append("</TR></TABLE></BODY>").append("<BR><BR>");
		builder.append("<BODY><TABLE ALIGN=CENTER VALIGN=CENTER><TR><TH>").append(titleEn).append("</TH></TR>");
		builder.append("<TR><TD><HR><FONT COLOR='red'>").append(messageEn).append("</FONT></HR></TD>");
		builder.append("</TR></TABLE></BODY>");

		out.println(builder.toString());
		response.flushBuffer();
	}

	/** 
	 * Load the info recorded in the database concerning an authentified user. If no record is found
	 * a new one is created then stored in the database for the next time we encounter the same
	 * user.
	 * @param authentifiedUser authentified user object
	 * @return a CSRUserInfo CSRUserInfo
	 * @throws ProfilesException custom exception related to profile errors
	 */
	protected CSRUserInfo notifyConnection(AuthentifiedUser authentifiedUser) throws ProfilesException {
		String login = authentifiedUser.getLogin();
		String mco = authentifiedUser.getMco();

		ProfilesRegistry profilesRegistry = ProfilesRegistry.getInstance();

		// --- try to retrieve existing userinfo
		CSRUserInfo userInfo = profilesRegistry.getUserInfo(login, mco);

		if (CSRToolUtil.isNull(userInfo)) {
			/*
			 * The program has never encountered this authentified user before. Create a new record
			 * in the database for him.
			 */
			userInfo = new CSRUserInfo();
			userInfo.setLogin(login);
			userInfo.setMco(mco);
			userInfo.setFirstname(authentifiedUser.getFirstname());
			userInfo.setLastname(authentifiedUser.getLastname());

			/*  Set the default language code for that new user. */
			McoFacade mcoFacade = McoFacade.get(mco);

			if (CSRToolUtil.isNotNull(mcoFacade)) {
				String[] languages = mcoFacade.getLanguages();
				if (CSRToolUtil.isNotNull(languages) && languages.length > 0) {
					userInfo.setLanguage(languages[0]);
				}
			}

			/*
			 * store the record in the database.
			 */
			profilesRegistry.createUserInfo(userInfo);
		} else {
			// finally, store the connection
			profilesRegistry.notifyConnection(userInfo);
		}

		// Set MCO name of CSR user in to upper case
		if(userInfo.getMco() != null) {
			userInfo.setMco(userInfo.getMco().trim().toUpperCase());
		}
		return userInfo;
	}

	/**
	 * Load the service role indicated by the authentified user
	 * @param authentifiedUser authentified user object
	 * @return a CSRRole
	 * @throws ProfilesException arises due to profile errors
	 */
	protected CSRRole loadRoles(AuthentifiedUser authentifiedUser) throws ProfilesException {
		if (authentifiedUser.getAdminLevel() == CSRPermission.ADMIN_LEVEL || authentifiedUser.getAdminLevel() == CSRPermission.WRITE_LEVEL) {
			return null;
		}

		String mco = authentifiedUser.getMco();
		String roleName = authentifiedUser.getServiceRoleName();

		try {
			ProfilesRegistry profilesRegistry = ProfilesRegistry.getInstance();
			return profilesRegistry.getRole(roleName, mco);
		} catch (ProfilesException e) {
			LOGGER.error(FuncLogging.getLogFormatedMessage("AuthentFilter","loadRoles",
					FuncLogging.REQUEST_STATUS_FAILED, null,e.getMessage()), e);
		throw new ProfilesException(ProfilesException.ROLE_DOES_NOT_EXISTS, new Object[] { roleName, mco });
		}
	}

	/**
	 * Let the authentification plugins verify if the user is correctly authentified.
	 * @param httpRequest HttpServletRequest
	 * @param currentUser CSRUser
	 * @return an AuthentifiedUser or <code>null</code> if no plugins could assert that the user
	 * is authentified.
	 */
	protected AuthentifiedUser getAuthentifiedUser(HttpServletRequest httpRequest, CSRUser currentUser) {

		for (IAuthentPlugin plugin : authentPlugins) {
			try {
				AuthentifiedUser authentifiedUser = plugin.getAuthentifiedUser(httpRequest, currentUser);
				if (CSRToolUtil.isNotNull(authentifiedUser)) {
					return authentifiedUser;
				}
			} catch (Exception e) {
				LOGGER.error( FuncLogging.getLogFormatedMessage("AuthentFilter","getAuthentifiedUser",FuncLogging.REQUEST_STATUS_FAILED, null," Error while authenticating current user: " + httpRequest.getUserPrincipal().getName()), e);
			}
		}

		return null;
	}

	/**
	 * Get the current user from the session
	 * @param httpRequest http request object
	 * @return a CSRUser or <code>null</code>
	 */
	protected CSRUser getSessionUser(HttpServletRequest httpRequest) {
		return BeanUtils.getBean(httpRequest, CSRUser.class, "curUser", Scope.Session);
	}

	/**
	 * Set the current user in the session
	 * @param httpRequest http servlet request object
	 * @param currentUser current csr user object
	 */
	protected void setSessionUser(HttpServletRequest httpRequest, CSRUser currentUser) {
		BeanUtils.setBean(httpRequest, currentUser, "curUser", Scope.Session);
	}

	/**
	 * Traces all header properties and values
	 * @param  httpRequest HTTP request object
	 */
	@SuppressWarnings("unchecked")
	protected void dumpAllHeaders(HttpServletRequest httpRequest) {
		StringBuilder bufToTrace = new StringBuilder();
		if (LOGGER.isTraceEnabled() ) {
			bufToTrace.append("http headers");
			for (String name : (List<String>) Collections.list(httpRequest.getHeaderNames())) {
				bufToTrace.append ("\n").append(String.format("%s = %s", name, httpRequest.getHeader(name)));
			}

			bufToTrace.append ("\nrequest scheme : ").append(httpRequest.getScheme());
			bufToTrace.append ("\nserver name : ").append(httpRequest.getServerName());
			bufToTrace.append ("\nserver port : ").append(httpRequest.getServerPort());
			bufToTrace.append ("\ncontext path : ").append(httpRequest.getContextPath());
			bufToTrace.append ("\ncontext path : ").append(httpRequest.getContextPath());
			bufToTrace.append ("\nBase tag will be: <base href=\"");
			bufToTrace.append(httpRequest.getScheme()).append("://").append(httpRequest.getServerName()).append(":");
			bufToTrace.append(httpRequest.getServerPort()).append(httpRequest.getContextPath()).append("/\" />");
			bufToTrace.append ("\ngetRemoteAddr : ").append(httpRequest.getRemoteAddr());
			bufToTrace.append ("\ngetRemoteHost : ").append(httpRequest.getRemoteHost());
			bufToTrace.append ("\ngetRemotePort : ").append(httpRequest.getRemotePort());
			bufToTrace.append ("\ngetRemoteUser : ").append(httpRequest.getRemoteUser());
			bufToTrace.append ("\ngetRequestURI : ").append(httpRequest.getRequestURI());

			LOGGER.trace(FuncLogging.getLogFormatedMessage("AuthentFilter","dumpAllHeaders",
					String.valueOf(FuncLogging.REQUEST_STATUS_SUCCESS), null,bufToTrace.toString()));
		}
	}


}
