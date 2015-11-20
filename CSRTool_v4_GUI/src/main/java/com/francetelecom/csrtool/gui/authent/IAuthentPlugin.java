package com.francetelecom.csrtool.gui.authent;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;

import com.francetelecom.csrtool.model.profiles.CSRUser;

/**
 * Interface for Initializing the Authentication Plugin
 * **/
public interface IAuthentPlugin {
	/**
	 * Initializes the authentication plug in
	 * @param iContext Servlet context object
	 * @throws Exception
	 */
	void init(ServletContext iContext) throws Exception;

	/**
	 * Analyzes the request and returns an object that identifies the authenticated user
	 * @param  iRequest HTTP request
	 * @param  currentUser Current CSR user
	 * @return Authenticated CSR user
	 * @throws Exception
	 */
	AuthentifiedUser getAuthentifiedUser(HttpServletRequest iRequest, CSRUser currentUser) throws Exception;
}
