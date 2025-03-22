package com.devsuperior.demo.config;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

// ATENÇÃO:
// -------
// esta classe não está sendo utilizada. Os métodos foram movidos
// sendo substituída pela classe ResourceServerConfig.java
//
// A clase SecurityConfig.java foi utilizada didaticamente para evolução do projeto


// adicionar no arquivo pom.xml as dependências do Spring Security

// classe criada para configurar o Spring Security
// os métodos aqui criados são componentes
@Configuration
public class SecurityConfig {

	// criação do componente para criptografar a senha do usuário
	@Bean
	public PasswordEncoder getPasswordEncoder() {

		return new BCryptPasswordEncoder();
	}

	@Bean
	@Profile("test")
	@Order(1)
	SecurityFilterChain h2SecurityFilterChain(HttpSecurity http) throws Exception {

		http.securityMatcher(PathRequest.toH2Console()).csrf(csrf -> csrf.disable())
				.headers(headers -> headers.frameOptions(frameOptions -> frameOptions.disable()));
		return http.build();
	}

	// criação do componente que cria a configuração do Spring Security
	@Bean
	@Order(2)
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

		// csrf.disable: desabilitando a proteção contra ataques csrf, acesso a dados da sessão
		// está sendo desabilitado porque esta API Rest não armazena dados na sessão, logo este controle não é necessário
		http.csrf(csrf -> csrf.disable());

		// configuração da permissão para os endpoint's, para as requisições
		// "anyRequest": todas as requisições, "permitAll": tudo permitido
		http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll());

		// aqui está sendo tudo permitido. As restrições necessárias serão configuradas em nível de rota

		return http.build();
	}
}