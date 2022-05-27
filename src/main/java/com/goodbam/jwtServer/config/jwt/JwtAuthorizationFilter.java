package com.goodbam.jwtServer.config.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.goodbam.jwtServer.config.auth.PrincipalDetails;
import com.goodbam.jwtServer.model.User;
import com.goodbam.jwtServer.repository.UserRepository;

// BasicAuthenticationFilter는 어떤 주소든 타게되는 필터임
public class JwtAuthorizationFilter extends BasicAuthenticationFilter{

	private UserRepository userRepository;
	
	public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
		super(authenticationManager);
		this.userRepository = userRepository;
	}
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {

		System.out.println("JwtAuthorization CLASS : 무조건 타게 되는 필터임");
		String jwtHeaderCheck = request.getHeader(JwtProperties.HEADER_STRING);

		if(jwtHeaderCheck == null || !jwtHeaderCheck.startsWith(JwtProperties.TOKEN_PREFIX)) {
			System.out.println("JwtAuthorization CLASS : 헤더의 데이터가 없거나 토큰 형식이 맞지 않음");
			chain.doFilter(request, response);
			return;
		}
		
		String jwtToken = request.getHeader(JwtProperties.HEADER_STRING).replace(JwtProperties.TOKEN_PREFIX, "");
		
		String username = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build().verify(jwtToken).getClaim("username").asString();
		
		if(username != null) {
			User userEntity = userRepository.findByusername(username);
			
			PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
			
			Authentication authentication =
					new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());
			
			SecurityContextHolder.getContext().setAuthentication(authentication);
			
			chain.doFilter(request, response);
		}
	}
}
