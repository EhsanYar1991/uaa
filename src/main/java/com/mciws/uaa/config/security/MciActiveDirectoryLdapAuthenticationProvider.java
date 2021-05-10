package com.mciws.uaa.config.security;

import org.apache.directory.shared.ldap.name.LdapDN;
import org.springframework.core.log.LogMessage;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.ldap.CommunicationException;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.ldap.core.support.DefaultDirObjectFactory;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.ldap.support.LdapUtils;
import org.springframework.security.authentication.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.ldap.SpringSecurityLdapTemplate;
import org.springframework.security.ldap.authentication.AbstractLdapAuthenticationProvider;

import javax.naming.*;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapName;
import java.io.Serializable;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class MciActiveDirectoryLdapAuthenticationProvider extends AbstractLdapAuthenticationProvider {

    private static final Pattern SUB_ERROR_CODE = Pattern.compile(".*data\\s([0-9a-f]{3,4}).*");

    // Error codes
    private static final int USERNAME_NOT_FOUND = 0x525;

    private static final int INVALID_PASSWORD = 0x52e;

    private static final int NOT_PERMITTED = 0x530;

    private static final int PASSWORD_EXPIRED = 0x532;

    private static final int ACCOUNT_DISABLED = 0x533;

    private static final int ACCOUNT_EXPIRED = 0x701;

    private static final int PASSWORD_NEEDS_RESET = 0x773;

    private static final int ACCOUNT_LOCKED = 0x775;

    private static final String SEARCH_FILTER_KEY = "filter";

    private final String domain ;

    private final String url;

    private boolean convertSubErrorCodesToExceptions;

    private final LdapContextSource ldapContextSource;
    private final PasswordEncoder passwordEncoder;

    public MciActiveDirectoryLdapAuthenticationProvider(final LdapContextSource ldapContextSource, PasswordEncoder passwordEncoder) {
        this.ldapContextSource = ldapContextSource;
        this.url = String.join(",",ldapContextSource.getUrls());
        this.domain = ldapContextSource.getBaseLdapPathAsString();
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected DirContextOperations doAuthentication(UsernamePasswordAuthenticationToken auth) {
        String username = auth.getName();
        String password = (String) auth.getCredentials();
        DirContext ctx = null;
        try {
            ctx = bindAsUser(username, password);
            DirContextOperations dirContextOperations = searchForUser(ctx, username);
            if (dirContextOperations == null || dirContextOperations.getNameInNamespace() == null || dirContextOperations.getNameInNamespace().trim().isEmpty()) {
                throw new BadCredentialsException("User not found");
            }
            String finalDn = dirContextOperations.getNameInNamespace();
            DirContext dirContext = ldapContextSource.getContext(
                    finalDn,
                    passwordEncoder.encode(password));
            if (dirContext == null) {
                throw new BadCredentialsException("Credential Error");
            }
            return dirContextOperations;
        } catch (CommunicationException ex) {
            throw badLdapConnection(ex);
        } catch (NamingException ex) {
            this.logger.error("Failed to locate directory entry for authenticated user: " + username, ex);
            throw badCredentials(ex);
        } finally {
            LdapUtils.closeContext(ctx);
        }
    }


    @SuppressWarnings("deprecation")
    @Override
    protected Collection<? extends GrantedAuthority> loadUserAuthorities(DirContextOperations userData, String username,
                                                                         String password) {
        String[] groups = userData.getStringAttributes("memberOf");
        if (groups == null) {
            this.logger.debug("No values for 'memberOf' attribute.");
            return AuthorityUtils.NO_AUTHORITIES;
        }
        if (this.logger.isDebugEnabled()) {
            this.logger.debug("'memberOf' attribute values: " + Arrays.asList(groups));
        }
        List<GrantedAuthority> authorities = new ArrayList<>(groups.length);
        for (String group : groups) {
            authorities.add(new SimpleGrantedAuthority(new DistinguishedName(group).removeLast().getValue()));
        }
        return authorities;
    }

    private DirContext bindAsUser(String username, String password) throws NamingException {
        Hashtable<String, Object> env = new Hashtable<>();
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        String bindPrincipal = createBindPrincipal(username);
        env.put(Context.SECURITY_PRINCIPAL, bindPrincipal);
        env.put(Context.PROVIDER_URL, this.url);
        env.put(Context.SECURITY_CREDENTIALS, password);
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.OBJECT_FACTORIES, DefaultDirObjectFactory.class.getName());
        if (ldapContextSource.getReadOnlyContext() != null && ldapContextSource.getReadOnlyContext().getEnvironment() != null) {
            ldapContextSource.getReadOnlyContext().getEnvironment().forEach((key, value) -> env.put((String) key, value));
        }
        try {
            return new InitialLdapContext(env, null);
        } catch (AuthenticationException | OperationNotSupportedException ex) {
            handleBindException(bindPrincipal, ex);
            throw badCredentials(ex);
        } catch (NamingException ex) {
            throw LdapUtils.convertLdapException(ex);
        }
    }

    private void handleBindException(String bindPrincipal, NamingException exception) {
        this.logger.debug(LogMessage.format("Authentication for %s failed:%s", bindPrincipal, exception));
        handleResolveObj(exception);
        int subErrorCode = parseSubErrorCode(exception.getMessage());
        if (subErrorCode <= 0) {
            this.logger.debug("Failed to locate AD-specific sub-error code in message");
            return;
        }
        this.logger.info(
                LogMessage.of(() -> "Active Directory authentication failed: " + subCodeToLogMessage(subErrorCode)));
        if (this.convertSubErrorCodesToExceptions) {
            raiseExceptionForErrorCode(subErrorCode, exception);
        }
    }

    private void handleResolveObj(NamingException exception) {
        Object resolvedObj = exception.getResolvedObj();
        boolean serializable = resolvedObj instanceof Serializable;
        if (resolvedObj != null && !serializable) {
            exception.setResolvedObj(null);
        }
    }

    private int parseSubErrorCode(String message) {
        Matcher matcher = SUB_ERROR_CODE.matcher(message);
        if (matcher.matches()) {
            return Integer.parseInt(matcher.group(1), 16);
        }
        return -1;
    }

    private void raiseExceptionForErrorCode(int code, NamingException exception) {
        String hexString = Integer.toHexString(code);
        Throwable cause = new MciActiveDirectoryAuthenticationException(hexString, exception.getMessage(), exception);
        switch (code) {
            case PASSWORD_EXPIRED:
                throw new CredentialsExpiredException(this.messages.getMessage(
                        "LdapAuthenticationProvider.credentialsExpired", "User credentials have expired"), cause);
            case ACCOUNT_DISABLED:
                throw new DisabledException(
                        this.messages.getMessage("LdapAuthenticationProvider.disabled", "User is disabled"), cause);
            case ACCOUNT_EXPIRED:
                throw new AccountExpiredException(
                        this.messages.getMessage("LdapAuthenticationProvider.expired", "User account has expired"), cause);
            case ACCOUNT_LOCKED:
                throw new LockedException(
                        this.messages.getMessage("LdapAuthenticationProvider.locked", "User account is locked"), cause);
            default:
                throw badCredentials(cause);
        }
    }

    private String subCodeToLogMessage(int code) {
        switch (code) {
            case USERNAME_NOT_FOUND:
                return "User was not found in directory";
            case INVALID_PASSWORD:
                return "Supplied password was invalid";
            case NOT_PERMITTED:
                return "User not permitted to logon at this time";
            case PASSWORD_EXPIRED:
                return "Password has expired";
            case ACCOUNT_DISABLED:
                return "Account is disabled";
            case ACCOUNT_EXPIRED:
                return "Account expired";
            case PASSWORD_NEEDS_RESET:
                return "User must reset password";
            case ACCOUNT_LOCKED:
                return "Account locked";
            default:
                return "Unknown (error code " + Integer.toHexString(code) + ")";
        }
    }

    private BadCredentialsException badCredentials() {
        return new BadCredentialsException(
                this.messages.getMessage("LdapAuthenticationProvider.badCredentials", "Bad credentials"));
    }

    private BadCredentialsException badCredentials(Throwable cause) {
        return (BadCredentialsException) badCredentials().initCause(cause);
    }

    private InternalAuthenticationServiceException badLdapConnection(Throwable cause) {
        return new InternalAuthenticationServiceException(this.messages.getMessage(
                "LdapAuthenticationProvider.badLdapConnection", "Connection to LDAP server failed."), cause);
    }

    private DirContextOperations searchForUser(DirContext context, String username) throws NamingException {
        SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        String searchFilter = (String) ldapContextSource.getReadOnlyContext().getEnvironment().get(SEARCH_FILTER_KEY);
        try {
            return SpringSecurityLdapTemplate.searchForSingleEntryInternal(context, searchControls, "",
                    searchFilter, new Object[]{username});
        } catch (CommunicationException ex) {
            throw badLdapConnection(ex);
        } catch (IncorrectResultSizeDataAccessException ex) {
            // Search should never return multiple results if properly configured -
            if (ex.getActualSize() != 0) {
                throw ex;
            }
            // If we found no results, then the username/password did not match
            UsernameNotFoundException userNameNotFoundException = new UsernameNotFoundException(
                    "User " + username + " not found in directory.", ex);
            throw badCredentials(userNameNotFoundException);
        }
    }


    String createBindPrincipal(String username) {
        if (this.domain == null || username.toLowerCase().endsWith(this.domain)) {
            return username;
        }
        return username + "@" + this.domain;
    }


    public void setConvertSubErrorCodesToExceptions(boolean convertSubErrorCodesToExceptions) {
        this.convertSubErrorCodesToExceptions = convertSubErrorCodesToExceptions;
    }

}
