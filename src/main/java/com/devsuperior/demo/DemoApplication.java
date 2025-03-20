package com.devsuperior.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class DemoApplication implements CommandLineRunner {

	@Autowired
	private PasswordEncoder passwordEncoder;

	public static void main(String[] args) {
		SpringApplication.run(DemoApplication.class, args);
	}

	/* teste de criptografia da senha (passwordEncoder.encode(String senha)) e a sua validação (passwordEncoder.matches(String senha, Srting hashcriptografadoparaconferencia))
	@Override
	public void run(String... args) throws Exception {

		// "123456" retorna o hash: "$2a$10$D3fW6d5YIK3yjZ/9qK8FDODWzYjgGQETyhWbqlQhcdQafQswIunJW"
		System.out.println("ENCONDE: " + passwordEncoder.encode("123456"));

		// teste para verificar a senha
		boolean senhavalida = passwordEncoder.matches("123456", "$2a$10$D3fW6d5YIK3yjZ/9qK8FDODWzYjgGQETyhWbqlQhcdQafQswIunJW");
		boolean senhainvalida = passwordEncoder.matches("1234567", "$2a$10$D3fW6d5YIK3yjZ/9qK8FDODWzYjgGQETyhWbqlQhcdQafQswIunJW");

		System.out.println("RESULTADO: " + senhavalida);
		System.out.println("RESULTADO: " + senhainvalida);
	}*/

	@Override
	public void run(String... args) throws Exception {

	}
}