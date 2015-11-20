package com.francetelecom.csrtool.gui.authent.plugins;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.builder.EqualsBuilder;

import com.francetelecom.clara.security.MissingUserPropertyException;
import com.francetelecom.csrtool.gui.authent.AuthentifiedUser;
import com.francetelecom.csrtool.gui.authent.IAuthentPlugin;
import static com.francetelecom.csrtool.gui.utils.BeanConstants.SEPERATOR_COMMA_STRING;
import com.francetelecom.csrtool.model.profiles.CSRUser;
import com.francetelecom.csrtool.utils.CSRToolUtil;

/**
 * 
 * An authentification plugin that reads authentification infos from request headers added by GASSI.
 * <p>the informations readed are:</p>
 * <table border=1 cellpadding=5> <tr>
 * <th>Information</th>
 * <th>GASSI Header</th> </tr> <tr>
 * <td>CSR User ID</td>
 * <td><i>sm_universalid</i></td> </tr> <tr>
 * <td>CSR User First name</td>
 * <td><i>ftusergivenname</i></td> </tr> <tr>
 * <td>CSR User Last name</td>
 * <td><i>ftusersn</i></td> </tr> <tr>
 * <td>MCO name</td>
 * <td><i>ftusercredentials</i></td> </tr> <tr>
 * <td>Administration role</td>
 * <td><i>ftapplicationroles</i></td> </tr> <tr>
 * <td>Application roles</td>
 * <td><i>ftapplicationroles</i></td> </tr> </table>
 * @class GassiAuthentPlugin 
 * @implements IAuthentPlugin
 */
public class GassiAuthentPlugin implements IAuthentPlugin {
	
	/**
	 * Initializes the authentication plug in
	 * @param context Servlet context object
	 * @throws Exception exception and its sub class of exceptionss
	 */
	public void init(ServletContext context) throws Exception {
		// do nothing
	}

	/**
	 * Analyzes the request and returns an object that identifies the authenticated user.
	 * @param  request HTTP request
	 * @param  currentUser Current CSR user
	 * @return Authenticated CSR user
	 * @throws MissingUserPropertyException custom exception if user property is missing
	 */
	public AuthentifiedUser getAuthentifiedUser(HttpServletRequest request, CSRUser currentUser) throws MissingUserPropertyException {
		/*
		 * Extract the user ID, MCO and the roles from the GASSI headers.
		 */
		String userId = getUserId(request);
		String userMCO = getMco(request);
		
		if (CSRToolUtil.isNotNull(currentUser)) {
			EqualsBuilder equalsBuilder = new EqualsBuilder();
			equalsBuilder.append(userId,currentUser.getLogin());
			equalsBuilder.append(userMCO,currentUser.getMco());
			if (equalsBuilder.isEquals()) {
				// Use the same user (do not decode HTTP headers)
				return null;
			}
		}

		/*
		 * Make and return authenticated user object
		 */
		List<String> roles = getRoles(request);
		String userFirstName = getFirstName(request);
		String userLastName = getLastName(request);
		return new AuthentifiedUser(userId, userFirstName, userLastName, userMCO, roles);
	}

	
	/**
	 * Gets the user id from the GASSI headers. 
	 * @param  request HTTP request
	 * @return user identifier
	 * @throws MissingUserPropertyException custom exception if user property is missing
	 */
	private String getUserId(HttpServletRequest request) throws MissingUserPropertyException {
		final String universalId = "sm_universalid";
		String userId = StringUtils.trimToNull(request.getHeader(universalId));

		if (CSRToolUtil.isNull(userId)) {
			throw new MissingUserPropertyException(universalId);
		}

		return userId;
	}

	/**
	 * Gets the user first name from the GASSI headers.
	 * @param  request HTTP request object
	 * @return user first name
	 * @throws MissingUserPropertyException custom exception if user property is missing
	 */
	private String getFirstName(HttpServletRequest request) throws MissingUserPropertyException {
		final String ftUserName = "ftusergivenname";
		String userFirstName = StringUtils.trimToNull(request.getHeader(ftUserName));

		if (CSRToolUtil.isNull(userFirstName)) {
			throw new MissingUserPropertyException(ftUserName);
		}

		return userFirstName;
	}

	/**
	 * Gets the user last name from the GASSI headers.
	 * @param  request HTTP request object
	 * @return last name of user
	 * @throws MissingUserPropertyException custom exception if user property is missing
	 */
	private String getLastName(HttpServletRequest request) throws MissingUserPropertyException {
		final String ftUserSn = "ftusersn";
		String userLastName = StringUtils.trimToNull(request.getHeader(ftUserSn));

		if (CSRToolUtil.isNull(userLastName)) {
			throw new MissingUserPropertyException(ftUserSn);
		}

		return userLastName;
	}

	/**
	 * Gets the user MCO.
	 * @param  request HTTP request object
	 * @return MCO
	 * @throws MissingUserPropertyException custom exception if user property is missing
	 */
	private String getMco(HttpServletRequest request) throws MissingUserPropertyException {
		String[] userCredentials = getUserCredentials(request);
		if(CSRToolUtil.isNotNull(userCredentials)) {
			return StringUtils.trimToNull(userCredentials[0]);
		} else {
			return null;
		}
	}

	/**
	 * Gets the roles.
	 * @param  request HTTP request object
	 * @return list of roles
	 * @throws MissingUserPropertyException custom exception if user property is missing
	 */
	List<String> getRoles(HttpServletRequest request) throws MissingUserPropertyException {
		List<String> roles = getRolesFromFTUserCredentials(request);
		if (CSRToolUtil.isNull(roles)) {
			roles = getRolesFromFTApplicationRoles(request);
		}

		return roles;
	}

	/**
	 * Gets the user roles from the 'ftusercredentials' GASSI header.
	 * @param  request HTTP request
	 * @return list of roles from FT user credentials
	 * @throws MissingUserPropertyException custom exception if user property is missing
	 */
	List<String> getRolesFromFTUserCredentials(HttpServletRequest request) throws MissingUserPropertyException {
		String[] userCredentials = getUserCredentials(request);

		if (CSRToolUtil.isNotNull(userCredentials) && userCredentials.length >= 3) {
			/* OK the credentials probably contains the role names */
			
			List<String> roles = new ArrayList<String>(2);
			roles.add(StringUtils.trimToNull(userCredentials[1]));
			roles.add(StringUtils.trimToNull(userCredentials[2]));

			return roles;
		}

		return null;
	}

	/**
	 * Get the roles from the request, that is from the 'ftapplicationroles' GASSI headers.
	 * @param  request HTTP request object
	 * @return list of roles from FT application roles
	 * @throws MissingUserPropertyException custom exception if user property is missing
	 */
	@SuppressWarnings("unchecked")
	private List<String> getRolesFromFTApplicationRoles(HttpServletRequest request) throws MissingUserPropertyException {
		final String ftApplRoles = "ftapplicationroles";
		String applicationRoles = StringUtils.trimToNull(request.getHeader(ftApplRoles));

		if (CSRToolUtil.isNull(applicationRoles)) {
			throw new MissingUserPropertyException(ftApplRoles);
		}

		/*
		 * Assume the applicationRoles is a list of ',' separated values. Each value contains the
		 * prefix which must be stripped
		 */
		String[] roles = applicationRoles.split(SEPERATOR_COMMA_STRING);
		for (int i = 0; i < roles.length; i++) {
			roles[i] = stripGassiPrefix(roles[i]);
		}

		return Arrays.asList(roles);
	}

	/**
	 * Gets the user credentials. We assume the user credentials is a list of ';' separated values.
	 * @param  request HTTP request object
	 * @return User credentials or <code>null</code> if the ftusercredentials is not provided.
	 * @throws MissingUserPropertyException custom exception if user property is missing
	 */
	String[] getUserCredentials(HttpServletRequest request) throws MissingUserPropertyException {
		String userCredentials = stripGassiPrefix(StringUtils.trimToNull(request.getHeader("ftusercredentials")));

		/*
		 * Assume the userCredentials is a list of ';' separated values.
		 */
		String[] userCred = null;
		if(CSRToolUtil.isNotNull(userCredentials)){
			userCred = userCredentials.split(";");
		} 
		
		return userCred;
	}

	/**
	 * Remove the prefix added by the GASSI from the given string.
	 * @param s given input string
	 * @return New String from where the GASSI prefix has been stripped.
	 */
	String stripGassiPrefix(String s) {
		
		String gassiPref = null;
		if(CSRToolUtil.isNotNull(s)) {
			gassiPref =  s.substring(s.indexOf(' ') + 1);
		} 
		return gassiPref;
	}
}
