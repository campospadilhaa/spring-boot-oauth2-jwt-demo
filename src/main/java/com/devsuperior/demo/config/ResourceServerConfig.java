package com.devsuperior.demo.config;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

// Classe que configura as permissões a nível das requisições
// se usuário mesmo autenticado tem permissão para acessar o recurso da aplicação

// CORS é um recurso dos navegadores que não permite que o backend seja
// acessado por um host não autorizado
// configurado em 'application.properties' os host's: 'http://localhost:3000' e 'http://localhost:5173'

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class ResourceServerConfig {

	// obtendo o contéudo da variável '${cors.origins}' a partir do application.properties
	@Value("${cors.origins}")
	private String corsOrigins;

	// liberado banco H2 para a realização de testes
	@Bean
	@Profile("test") // perfil de teste
	@Order(1)
	public SecurityFilterChain h2SecurityFilterChain(HttpSecurity http) throws Exception {

		http.securityMatcher(PathRequest.toH2Console()).csrf(csrf -> csrf.disable())
				.headers(headers -> headers.frameOptions(frameOptions -> frameOptions.disable()));
		return http.build();
	}

	// 
	@Bean
	@Order(3)
	public SecurityFilterChain rsSecurityFilterChain(HttpSecurity http) throws Exception {

		// liberado o recurso CSRF porque esta aplicação é backend, não utiliza sessão
		http.csrf(csrf -> csrf.disable());

		// por padrão está tudo permitido 'permitAll'. As restrições serão configuradas por rota/serviço (endpoint)
		http.authorizeHttpRequests(authorize -> authorize.anyRequest().permitAll());

		// o ResourceServer receberá um token no formato JWT
		http.oauth2ResourceServer(oauth2ResourceServer -> oauth2ResourceServer.jwt(Customizer.withDefaults()));

		// passando os bean's configurados mais abaixo contendo os CORS configurados, host's liberados
		http.cors(cors -> cors.configurationSource(corsConfigurationSource()));

		return http.build();
	}

	// configuração do JWT
	@Bean
	public JwtAuthenticationConverter jwtAuthenticationConverter() {

		JwtGrantedAuthoritiesConverter grantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
		grantedAuthoritiesConverter.setAuthoritiesClaimName("authorities");
		grantedAuthoritiesConverter.setAuthorityPrefix("");

		JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
		jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(grantedAuthoritiesConverter);
		return jwtAuthenticationConverter;
	}

	// configurações dos CORS
	@Bean
	CorsConfigurationSource corsConfigurationSource() {

		// obtém os host's configurados
		String[] origins = corsOrigins.split(",");

		CorsConfiguration corsConfig = new CorsConfiguration();

		// atribui a lista de 'origins' permitidas
		corsConfig.setAllowedOriginPatterns(Arrays.asList(origins));

		// quais métodos permitidos
		corsConfig.setAllowedMethods(Arrays.asList("POST", "GET", "PUT", "DELETE", "PATCH"));

		corsConfig.setAllowCredentials(true);
		corsConfig.setAllowedHeaders(Arrays.asList("Authorization", "Content-Type"));

		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", corsConfig);

		return source;
	}

	@Bean
	FilterRegistrationBean<CorsFilter> corsFilter() {
		FilterRegistrationBean<CorsFilter> bean = new FilterRegistrationBean<>(
				new CorsFilter(corsConfigurationSource()));
		bean.setOrder(Ordered.HIGHEST_PRECEDENCE);
		return bean;
	}
	////
}
