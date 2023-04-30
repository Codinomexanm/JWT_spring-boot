package com.novidades.gestaodeprojetos.services;

import java.util.InputMismatchException;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.novidades.gestaodeprojetos.model.Usuario;
import com.novidades.gestaodeprojetos.respository.UsuarioRepository;

@Service
public class UsuarioService {
  @Autowired
  private UsuarioRepository repositorioUsuario;

  @Autowired
  private PasswordEncoder passwordEncoder;

  public List<Usuario> obterTodos() {
    return repositorioUsuario.findAll();
  }

  public Optional<Usuario> obterPorId(Long id) {
    return repositorioUsuario.findById(id);
  }

  public Optional<Usuario> obterPorEmail(String email) {
    return repositorioUsuario.findByEmail(email);
  }

  public Usuario adicionar(Usuario usuario) {
    usuario.setId(null);
    if (obterPorEmail(usuario.getEmail()).isPresent()) {
      // aqui poderia lançar um expection informando que o usuário já existe.
      throw new InputMismatchException("Já existe um usuario cadastrado com o email: " + usuario.getEmail());
    }
    // aqui estou codificando a senha para não se tornar publica, gerando rash
    String senha = passwordEncoder.encode(usuario.getSenha());
    usuario.setSenha(senha);
    return repositorioUsuario.save(usuario);
  }

}
