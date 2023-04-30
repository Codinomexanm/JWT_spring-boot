package com.novidades.gestaodeprojetos.security;

import java.util.Date;
import java.util.Optional;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import com.novidades.gestaodeprojetos.model.Usuario;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JWTService {
  // chave secreta utilizada pela jwt para codificar e decodificar o token
  private static final String chavePrivadaJwt = "secretKey";

  /**
   * método para gerar o token JWT
   * 
   * @param authentication Autenticação do usuário;
   * @return token
   */

  public String gerarToken(Authentication authentication) {
    // um dia em milissencods
    int tempoExpiracao = 86400000;
    // aqui estou criando um data de expiração para o token com base no tempo de
    // expiração
    // ele pega a data atual e soma + um dia em milissegundos
    Date dataExpiracao = new Date(new Date().getTime() + tempoExpiracao);
    // aqui pegamos o usuário atual da autenticação
    Usuario usuario = (Usuario) authentication.getPrincipal();
    // aqui ele pega todos os dados e me retornar um token bonito JWT
    return Jwts.builder()
        .setSubject(usuario.getId().toString())
        .setIssuedAt(new Date())
        .setExpiration(dataExpiracao)
        .signWith(SignatureAlgorithm.HS512, chavePrivadaJwt)
        .compact();
  }

  /**
   * método para retornar o id od usuário dono do token
   * 
   * @param token token do usuário;
   * @return id do usuário
   */
  public Optional<Long> ObterIdDoUsuario(String token) {
    try {
      // Retorna as permissões do token
      Claims claims = parse(token).getBody();
      // retorna o id de dentro do token se encontrar caso contrario retornar Nullo
      return Optional.ofNullable(Long.parseLong(claims.getSubject()));
    } catch (Exception e) {
      // se não encontrar nada retornar um optional null
      return Optional.empty();
    }
  }

  // Metodo que sabe descobrir de dentro do token bom base na chave privada qual
  // as permissões do usuário
  private Jws<Claims> parse(String token) {
    return Jwts.parser().setSigningKey(chavePrivadaJwt).parseClaimsJws(token);
  }
}
