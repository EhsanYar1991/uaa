package com.mciws.uaa.config.security;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.log.LogMessage;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.ldap.core.ContextSource;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.support.LdapContextSource;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.ldap.SpringSecurityLdapTemplate;
import org.springframework.security.ldap.search.LdapUserSearch;
import org.springframework.util.Assert;

import javax.naming.NamingException;
import javax.naming.directory.SearchControls;


public class MciFilterBasedLdapUserSearch implements LdapUserSearch {

    private static final Log logger = LogFactory.getLog(org.springframework.security.ldap.search.FilterBasedLdapUserSearch.class);

    private static final String FILTER_SEARCH_KEY = "filter";

    private final ContextSource contextSource;


    private final SearchControls searchControls = new SearchControls();

    private String searchBase = "";


    private String searchFilter;

    public MciFilterBasedLdapUserSearch(LdapContextSource contextSource) {
        Assert.notNull(contextSource, "contextSource must not be null");
        this.contextSource = contextSource;
        try {
            this.searchFilter = (String) contextSource.getReadOnlyContext().getEnvironment().get(FILTER_SEARCH_KEY);
        } catch (NamingException e) {
            logger.info("Search fillter must be determined");
        }
        setSearchSubtree(true);
        if (searchBase.length() == 0) {
            logger.info(
                    "SearchBase not set. Searches will be performed from the root: " + contextSource.getBaseLdapPath());
        }
    }


    @Override
    public DirContextOperations searchForUser(String username) {
        logger.debug(LogMessage.of(() -> "Searching for user '" + username + "', with user search " + this));
        SpringSecurityLdapTemplate template = new SpringSecurityLdapTemplate(this.contextSource);
        template.setSearchControls(this.searchControls);
        try {
            return template.searchForSingleEntry(this.searchBase, this.searchFilter, new String[] { username });
        }
        catch (IncorrectResultSizeDataAccessException ex) {
            if (ex.getActualSize() == 0) {
                throw new UsernameNotFoundException("User " + username + " not found in directory.");
            }
            // Search should never return multiple results if properly configured
            throw ex;
        }
    }


    public void setDerefLinkFlag(boolean deref) {
        this.searchControls.setDerefLinkFlag(deref);
    }


    public void setSearchSubtree(boolean searchSubtree) {
        this.searchControls
                .setSearchScope(searchSubtree ? SearchControls.SUBTREE_SCOPE : SearchControls.ONELEVEL_SCOPE);
    }


    public void setSearchTimeLimit(int searchTimeLimit) {
        this.searchControls.setTimeLimit(searchTimeLimit);
    }


    public void setReturningAttributes(String[] attrs) {
        this.searchControls.setReturningAttributes(attrs);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("[ searchFilter: '").append(this.searchFilter).append("', ");
        sb.append("searchBase: '").append(this.searchBase).append("'");
        sb.append(", scope: ").append(
                (this.searchControls.getSearchScope() != SearchControls.SUBTREE_SCOPE) ? "single-level, " : "subtree");
        sb.append(", searchTimeLimit: ").append(this.searchControls.getTimeLimit());
        sb.append(", derefLinkFlag: ").append(this.searchControls.getDerefLinkFlag()).append(" ]");
        return sb.toString();
    }

}
