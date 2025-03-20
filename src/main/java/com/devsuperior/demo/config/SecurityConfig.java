package com.devsuperior.demo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

// adicionar no arquivo pom.xml as dependências do Spring Security

// classe criada para configurar o Spring Security
@Configuration
public class SecurityConfig {

	@Bean
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