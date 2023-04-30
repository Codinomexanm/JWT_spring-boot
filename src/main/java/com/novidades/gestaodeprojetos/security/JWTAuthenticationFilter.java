package com.novidades.gestaodeprojetos.security;

import java.io.IOException;
import java.util.Collections;
import java.util.InputMismatchException;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JWTAuthenticationFilter extends OncePerRequestFilter {
  @Autowired
  private JWTService jwtService;
  @Autowired
  private CustomUserDetailsService customUserDetailsService;

  // método principal aonde tod a requisição bate antes de chegar no nosso
  // endPoint
  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    // pego o token de dentro da requisição
    String token = obterToken(request);
    // pego o id do usuário que está dentro do token.
    Optional<Long> id = jwtService.ObterIdDoUsuario(token);

    if (!id.isPresent()) {
      throw new InputMismatchException("token Inválido");
    }
    // pego o usuário dono do token pelo seu Id.
    UserDetails usuario = customUserDetailsService.obeterUsuarioPorId(id.get());
    // nesse ponto verificamos se o usuário está autenticado ou não.
    // aqui também poderíamos validar as permissões
    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(usuario, null,
        Collections.emptyList());

    // mudando a autenticação para a própria requisição .
    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
    // repasso a autenticação para o contexto o security
    // a partir de agora o spring toma conta de tudo
    SecurityContextHolder.getContext().setAuthentication(authentication);
  }

  private String obterToken(HttpServletRequest request) {
    String token = request.getHeader("Authorization");

    // verifica se veio alguma coisa sem ser espaços em branco dentro do token
    if (!StringUtils.hasText(token)) {
      return null;
    }
    return token.substring(7);
  }

}
