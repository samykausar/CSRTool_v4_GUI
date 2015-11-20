package com.francetelecom.csrtool.gui.authent;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.builder.EqualsBuilder;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.apache.commons.lang3.builder.ToStringBuilder;

import com.francetelecom.csrtool.model.profiles.CSRPermission;
import com.francetelecom.csrtool.utils.CSRToolUtil;

/**
 * This bean represents the authenticated user.
 * @class AuthentifiedUser
 * @Implements Serializable
 */
public class AuthentifiedUser implements Serializable {
	
	/**	serialVersionUID **/
	private static final long serialVersionUID = -2831620456882878663L;

	/**	none admin **/
	private static final String ADMIN_NONE = "admin_none";
	
	/**	read admin **/
	private static final String ADMIN_READ = "admin_read";
	
	/**	write admin **/
	private static final String ADMIN_WRITE = "admin_write";
	
	/**	all mco admin **/
	private static final String ADMIN_ALL_MCO = "admin_allmco";

	/**	login **/
	private String login;
	
	/**	firstname **/
	private String firstname;
	
	/**	lastname **/
	private String lastname;
	
	/**	mco **/
	private String mco;
	
	/**	service role name **/
	private String serviceRoleName;
	
	/**	adminLevel **/
	private int adminLevel;
	
	/**	role names **/
	private Collection<String> roleNames;

	/**
	 * An exception thrown by the {@link AuthentifiedUser#verifyRoleCoherence()} method.
	 * @class ValidationException
	 * @extends Exception
	 */
	public static class ValidationException extends Exception {
		/**
		 * Validation Exception
		 * @param message String
		 * **/
		public ValidationException(String message) {
			super(message);
		}
	}

	/**
	 * Constructor
	 * @param userId user identifier
	 * @param firstname user firstname
	 * @param lastName user last name
	 * @param mco mco
	 * @param roles collection of roles
	 */
	public AuthentifiedUser(String userId, String firstname, String lastName, String mco, Collection<String> roles) {
		this.login = userId;
		this.firstname = firstname;
		this.lastname = lastName;
		this.mco = mco;
		this.roleNames = roles;
	}

	/**
	 * Verify the coherence of the roles coming with this AuthentifiedUser
	 * @throws ValidationException
	 */
	public void validate() throws ValidationException {
		if (CSRToolUtil.isNull(StringUtils.trimToNull(login))) {
			throw new ValidationException("Access denied: the login given by GASSI is null or empty (" + toString() + ")");
		}

		/*
		 * Recognize the admin levels.
		 */
		List<String> recognizedAdminLevelNames = new ArrayList<String>();
		for (String roleName : this.roleNames) {
			if (ADMIN_NONE.equalsIgnoreCase(roleName)) {
				adminLevel = CSRPermission.NONE_LEVEL;
				recognizedAdminLevelNames.add(roleName);
			} else if (ADMIN_READ.equalsIgnoreCase(roleName)) {
				adminLevel = CSRPermission.READ_LEVEL;
				recognizedAdminLevelNames.add(roleName);
			} else if (ADMIN_WRITE.equalsIgnoreCase(roleName)) {
				adminLevel = CSRPermission.WRITE_LEVEL;
				recognizedAdminLevelNames.add(roleName);
			} else if (ADMIN_ALL_MCO.equalsIgnoreCase(roleName)) {
				adminLevel = CSRPermission.ADMIN_LEVEL;
				recognizedAdminLevelNames.add(roleName);
			}
		}

		/*
		 * Count the number of recognized admin and service roles name.
		 */
		int adminLevelCount = recognizedAdminLevelNames.size();
		int serviceRoleCount = this.roleNames.size() - adminLevelCount;

		/*
		 * One and only one admin level is accepted.
		 */
		if (adminLevelCount == 0) {
			throw new ValidationException("Access denied: no admin level defined(" + toString() + ")");
		} else if (adminLevelCount > 1) {
			throw new ValidationException("Access denied: too many admin level defined: " + recognizedAdminLevelNames + "(" + toString() + ")");
		}

		/*
		 * One and only one role is accepted except if the admin level is
		 * Admin_allMCO in which case no role is expected
		 */
		if (adminLevel != CSRPermission.ADMIN_LEVEL && adminLevel != CSRPermission.WRITE_LEVEL) {
			if (serviceRoleCount == 0) {
				throw new ValidationException("Access denied: no service role defined (" + toString() + ")");
			} else {
				/* Duplicate the collection then remove all admin level from it,
				   we should be left with the unique service role name. */
				List<String> serviceRoleNames = new ArrayList<String>(this.roleNames);
				serviceRoleNames.removeAll(recognizedAdminLevelNames);

				if (serviceRoleCount > 1) {
					throw new ValidationException("Access denied: too many roles defined: " + serviceRoleNames + "(" + toString() + ")");
				}

				serviceRoleName = serviceRoleNames.get(0);
			}
		}

		/*
		 * the mco should be null for admin_allmco users
		 */
		if (adminLevel != CSRPermission.ADMIN_LEVEL && CSRToolUtil.isNull(mco)) {
				throw new ValidationException("Access denied: no mco defined (" + toString() + ")");
		}

	}
	

	/*----------------------------
	  Utilities
	  ----------------------------*/
	/**
	 * @return details of user
	 **/
	@Override
	public String toString() {
		ToStringBuilder toStringBuilder = new ToStringBuilder(this);
		toStringBuilder.appendSuper(super.toString());
		toStringBuilder.append("login", login);
		toStringBuilder.append("firstname", firstname);
		toStringBuilder.append("lastname", lastname);
		toStringBuilder.append("mco", mco);
		toStringBuilder.append("roles service & admin", roleNames);
		
		return toStringBuilder.toString();
	}

	/**
	 *  @param obj of Object type
	 *  @return whether objects are equal or not
	 * **/
	@Override
	public boolean equals(Object obj) {
		if (CSRToolUtil.isNull(obj)) {
			return false;
		}
		if (obj == this) {
			return true;
		}
		if (obj.getClass() != getClass()) {
			return false;
		}
		AuthentifiedUser rhs = (AuthentifiedUser) obj;
		EqualsBuilder equalsBuilder = new EqualsBuilder();
		equalsBuilder.appendSuper(super.equals(obj));
		equalsBuilder.append(login, rhs.login);
		equalsBuilder.append(mco, rhs.mco);
		return equalsBuilder.isEquals();
	}

	/**
	 * @return hashcoded integer value
	 **/
	@Override
	public int hashCode() {
		HashCodeBuilder hashCodeBuilder = new HashCodeBuilder();
		hashCodeBuilder.appendSuper(super.hashCode());
		hashCodeBuilder.append(login);
		hashCodeBuilder.append(mco);
		return hashCodeBuilder.toHashCode();
	}
	
	
	/*----------------------------
	  Getters & Setters
	  ----------------------------*/
	/**
	 * @return login detail
	 * **/
	public String getLogin() {
		return login;
	}

	/**
	 * @return user first name
	 * **/
	public String getFirstname() {
		return firstname;
	}

	/**
	 *	@return user last name 
	 **/
	public String getLastname() {
		return lastname;
	}

	/**
	 * @return mco 
	 **/
	public String getMco() {
		return mco;
	}

	/**
	 * @return administrator level
	 **/
	public int getAdminLevel() {
		return adminLevel;
	}

	/**
	 * @return service role name
	 **/
	public String getServiceRoleName() {
		return serviceRoleName;
	}

}
