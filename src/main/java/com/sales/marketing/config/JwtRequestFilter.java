package com.sales.marketing.config;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Properties;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.reactive.ClientHttpConnector;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.reactive.function.client.WebClient;

import io.netty.channel.ChannelOption;
import io.netty.handler.timeout.ReadTimeoutHandler;
import io.netty.handler.timeout.WriteTimeoutHandler;
import reactor.netty.http.client.HttpClient;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {

	@Autowired
	private JwtTokenUtil jwtTokenUtil;

	private final Logger logger = LoggerFactory.getLogger(this.getClass());

		
	String validateUserURL = null;
	private Properties myProperties;	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {

		//get validateUserURL from config.properties file 
		//decoded password string declaration
		String decodedpassword = null;
		myProperties = new Properties();
		InputStream input = JwtRequestFilter.class.getClassLoader().getResourceAsStream("config.properties");
		myProperties.load(input);
		String authUrl = myProperties.getProperty("api.auth.url");
		validateUserURL = authUrl + "/auth/validateUser";
		logger.debug("validate Url : " + validateUserURL);
		
		
		
		logger.debug("User Name Received in the Header: " + request.getHeader("UserName"));

		final String requestTokenHeader = request.getHeader("Authorization");
		final boolean encodedAcceessKey = request.getHeader("UserName") != null; // Access key is sent as UserName in
																					// the Header
		boolean basicAuth = false;
		// TODO - Temporary header value that will be removed later when verify against
		// DB users
		final String requestPrincipleHeader = encodedAcceessKey ? request.getHeader("UserName")
				: request.getHeader("UserId");

		logger.debug("Headers- Authotization: " + requestTokenHeader + "UserId/UserName:" + requestPrincipleHeader);

		String username = null;
		String jwtToken = null;
		String decodeduserName = null;
		boolean tokenValidated = false;
		
		 
		
		// JWT Token is in the form "Bearer token". Remove Bearer word and get
		// only the Token
		if (requestTokenHeader != null && requestTokenHeader.startsWith("Bearer ")) {
			jwtToken = requestTokenHeader.substring(7);
		} else if (requestTokenHeader != null && requestTokenHeader.startsWith("Basic ")) {
			jwtToken = requestTokenHeader.substring(6);
			basicAuth = true;
		}
		if (basicAuth) {
			logger.debug("Encoded Access key sent, So Decoding");
			// username = new String(Base64.getDecoder().decode(requestPrincipleHeader));
			String decodedBasicAuth = new String(Base64.getDecoder().decode(jwtToken));
			String[] tokens = decodedBasicAuth.split(":");
			decodeduserName = tokens[0];
			
			// get password from JWT Token
			decodedpassword = tokens[1];
			
			
			username = decodeduserName;
		} else {
			username = requestPrincipleHeader;
		}

		// Once we get the token validate it.
		if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

			// UserDetails userDetails =
			// this.jwtUserDetailsService.loadUserByUsername(username);
			UserDetails userDetails = new User(username, "$2a$10$dKxiIMfQh.yCktH8ImPXbu5/B/e1a4UurQ6fAMr2JPOAImi6oBpEe",
					new ArrayList<>());

			// if token is valid configure Spring Security to manually set
			
			// authentication
			if (basicAuth) { // Basic Auth
				// TODO - Get Password tokens[1] and validate user against the Database in
				// Future
				
				//	For validate username and password		
  					
				
				if (decodeduserName.equals(username)) {
					logger.debug("Basic Auth Token validated");
					tokenValidated = true;
				}
				
				////////////////////DB cALL validation				
				//dbcall		
				tokenValidated = validateUser(decodeduserName, decodedpassword) ; 
				
				

			} else { // Bearer Token Auth
				if (jwtTokenUtil.validateToken(jwtToken, username)) {
					logger.debug("Bearer auth Token validated");
					tokenValidated = true;
				}
			}
			if (tokenValidated) {
				UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
						userDetails, null, userDetails.getAuthorities());
				usernamePasswordAuthenticationToken
						.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				// After setting the Authentication in the context, we specify
				// that the current user is authenticated. So it passes the
				// Spring Security Configurations successfully.
				SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
			}

		}
		
		
		chain.doFilter(request, response);
	}
	
	//validateUser() method call from authTokenService 
	 
	private Boolean validateUser(String username, String password) {
		String response = null;
		response = getWebClient().post().uri(uriBuilder -> uriBuilder.queryParam("username", username)
				.queryParam("password", password).queryParam("apiId", "").build()).retrieve().bodyToFlux(String.class)
				.blockFirst();
		return Boolean.parseBoolean(response);

	}

	private WebClient getWebClient() {
		HttpClient httpClient = HttpClient.create()
				.tcpConfiguration(client -> client.option(ChannelOption.CONNECT_TIMEOUT_MILLIS, new Integer(300 * 1000))
						.doOnConnected(conn -> conn.addHandlerLast(new ReadTimeoutHandler(300))
								.addHandlerLast(new WriteTimeoutHandler(300))));
		ClientHttpConnector connector = new ReactorClientHttpConnector(httpClient);

		WebClient wc = WebClient.builder().baseUrl(this.validateUserURL).clientConnector(connector)
				.defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
				.defaultHeader(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON_VALUE).build();
		return wc;
	}
	
}
