package io.jctiru.springbootmicroservicessandboxapigateway.security;

import java.io.IOException;
import java.util.ArrayList;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;

@Component
public class AuthorizationFilter extends BasicAuthenticationFilter {

	@Autowired
	private Environment env;

	@Autowired
	public AuthorizationFilter(@Lazy AuthenticationManager authenticationManager) {
		super(authenticationManager);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		String header = req.getHeader(env.getProperty("authorization.token.header.name"));

		if (header == null || !header.startsWith(env.getProperty("authorization.token.header.prefix"))) {
			chain.doFilter(req, res);
			return;
		}

		UsernamePasswordAuthenticationToken authentication = getAuthentication(req);
		SecurityContextHolder.getContext().setAuthentication(authentication);
		chain.doFilter(req, res);
	}

	private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
		String token = request.getHeader(env.getProperty("authorization.token.header.name"));

		if (token != null) {
			token = token.replace(env.getProperty("authorization.token.header.prefix"), "");

			Jws<Claims> parsedToken = Jwts.parser()
					.setSigningKey(env.getProperty("token.secret"))
					.parseClaimsJws(token);

			String userId = parsedToken.getBody().getSubject();

			if (userId != null) {
				return new UsernamePasswordAuthenticationToken(userId, null, new ArrayList<>());
			}
		}

		return null;
	}

}
