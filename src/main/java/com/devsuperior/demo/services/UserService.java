package com.devsuperior.demo.services;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.devsuperior.demo.entities.Role;
import com.devsuperior.demo.entities.User;
import com.devsuperior.demo.projections.UserDetailsProjection;
import com.devsuperior.demo.repositories.UserRepository;

// classe criada que UserDetailsService para realizar a busca do usuário pelo 'username' informado
@Service
public class UserService implements UserDetailsService {

	@Autowired
	UserRepository userRepository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

		/*
	    método substituído porque por default os 'roles' não acompanham o 'User' o
	    relacionamento muitos para muitos tem o comportamento LAZY. Seria possível
	    forçar este retorno configurando o relacionamento com FetchType.EAGER no bean User
	    porém, não é uma boa prática, isto porque nem sempre desejaremos o User com os seus roles.
	    Então substituímos pelo método abaixo 'searchUserAndRolesByEmail(String)' que contém
	    a query escrita na mão
		User user = userRepository.findByEmail(username);*/

		List<UserDetailsProjection> listaUserDetailsProjection = userRepository.searchUserAndRolesByEmail(username);
		if(listaUserDetailsProjection==null || listaUserDetailsProjection.isEmpty()) {
			throw new UsernameNotFoundException("Atenção: Usuário não encontrado!");
		}

		User user = new User();
		user.setEmail(username);
		user.setPassword(listaUserDetailsProjection.get(0).getPassword());

		for (UserDetailsProjection userDetailsProjection : listaUserDetailsProjection) {

			user.addRole(new Role(userDetailsProjection.getRoleId(), userDetailsProjection.getAuthority()));
		}

		return user;
	}
}