package com.devsuperior.demo.entities;

import java.time.LocalDate;
import java.util.Collection;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;

@SuppressWarnings("serial")
@Entity
@Table(name = "tb_user")
public class User implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String name;

    @Column(unique = true)
    private String email;

    private String password;

    // relacionamento muitos para muitos não retorna a lista de roles, relacionametno LAZY
    // para forçar este retorno é possível configurar o relacionamento com FetchType.EAGER
    // porém, não é uma boa prática, isto porque nem sempre desejaremos o User com os seus roles
    //@ManyToMany(fetch = FetchType.EAGER)
    @ManyToMany
    @JoinTable(name = "tb_user_role",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<Role> roles = new HashSet<>();

    public User() {

    }

    public User(Long id, String name, String email, String phone, LocalDate birthDate, String password) {
        this.id = id;
        this.name = name;
        this.email = email;
        this.password = password;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    // método para adicionar permissões
    public void addRole(Role role) {
    	roles.add(role);
    }

    // método para verificação se o usuário possui determinado Role passado por argumento
    public boolean hasRole(String roleName) {

    	for (Role role : roles) {
			if(role.getAuthority().equals(roleName)) {
				return true;
			}
		}

    	return false;
    }

    @Override
    public boolean equals(Object o) {

    	if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        User user = (User) o;

        return Objects.equals(id, user.id);
    }

    @Override
    public int hashCode() {
        return id != null ? id.hashCode() : 0;
    }

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {

		// retorna a lista de "roles" que implementa "GrantedAuthority"
		return roles;
	}

	@Override
	public String getUsername() {

		// retorna o atributo "email" que será utilizado como o username
		return email;
	}

	// atribuido o valor true porque neste projeto não utilizaremos estes métodos necessários para a interface "UserDetails"
	@Override
	public boolean isAccountNonExpired() {
		//return false;
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		//return false;
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		//return false;
		return true;
	}

	@Override
	public boolean isEnabled() {
		//return false;
		return true;
	}
	////
}