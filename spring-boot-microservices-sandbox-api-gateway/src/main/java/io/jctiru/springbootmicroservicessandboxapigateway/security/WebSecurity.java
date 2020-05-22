package io.jctiru.springbootmicroservicessandboxapigateway.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

@EnableWebSecurity
public class WebSecurity extends WebSecurityConfigurerAdapter {

	@Autowired
	private Environment env;

	@Override
	public void configure(HttpSecurity http) throws Exception {
		http.csrf().disable()
				.authorizeRequests()
				.antMatchers(HttpMethod.GET, env.getProperty("api.statuscheck.url.path")).permitAll()
				.antMatchers(env.getProperty("api.h2console.url.path")).permitAll()
				.antMatchers(HttpMethod.POST, env.getProperty("api.registration.url.path")).permitAll()
				.antMatchers(HttpMethod.POST, env.getProperty("api.login.url.path")).permitAll()
				.anyRequest().authenticated()
				.and()
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				.and()
				.headers().frameOptions().disable();
	}

}
