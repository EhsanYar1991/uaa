package com.mciws.uaa.config.security;

import com.fasterxml.classmate.TypeResolver;
import com.google.common.collect.Multimap;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.web.bind.annotation.RequestMethod;
import springfox.documentation.builders.ApiListingBuilder;
import springfox.documentation.builders.OperationBuilder;
import springfox.documentation.builders.ParameterBuilder;
import springfox.documentation.schema.ModelRef;
import springfox.documentation.service.ApiDescription;
import springfox.documentation.service.ApiListing;
import springfox.documentation.service.Operation;
import springfox.documentation.service.ResponseMessage;
import springfox.documentation.spi.service.contexts.Defaults;
import springfox.documentation.spring.web.plugins.DocumentationPluginsManager;
import springfox.documentation.spring.web.readers.operation.CachingOperationNameGenerator;
import springfox.documentation.spring.web.scanners.ApiDescriptionReader;
import springfox.documentation.spring.web.scanners.ApiListingScanner;
import springfox.documentation.spring.web.scanners.ApiListingScanningContext;
import springfox.documentation.spring.web.scanners.ApiModelReader;

import java.util.*;
import java.util.stream.Collectors;

public class FormLoginOperations extends ApiListingScanner {
    @Autowired
    private TypeResolver typeResolver;

    @Autowired
    public FormLoginOperations(ApiDescriptionReader apiDescriptionReader, ApiModelReader apiModelReader, DocumentationPluginsManager pluginsManager) {
        super(apiDescriptionReader, apiModelReader, pluginsManager);
    }

    @Override
    public Multimap<String, ApiListing> scan(ApiListingScanningContext context) {

        Defaults defaults = new Defaults();
        Set<ResponseMessage> collect = defaults.defaultResponseMessages().get(RequestMethod.POST).stream().collect(Collectors.toSet());

        final Multimap<String, ApiListing> def = super.scan(context);

        final List<ApiDescription> apis = new LinkedList<>();

        final List<Operation> operations = new ArrayList<>();
        operations.add(new OperationBuilder(new CachingOperationNameGenerator())
                .method(HttpMethod.POST)
                .summary("Login Api")
                .uniqueId("login")
                .parameters(Arrays.asList(new ParameterBuilder()
                                .name("username")
                                .description("The username")
                                .parameterType("query")
                                .type(typeResolver.resolve(String.class))
                                .modelRef(new ModelRef("string"))
                                .build(),
                        new ParameterBuilder()
                                .name("password")
                                .description("The password")
                                .parameterType("query")
                                .type(typeResolver.resolve(String.class))
                                .modelRef(new ModelRef("string"))
                                .build()))
                .summary("Log in") //
                .notes("Here you can log in")
                .responseMessages(collect)
                .responseModel(new ModelRef("string"))
                .build());
        apis.add(new ApiDescription("Authentication", "/login", "Authentication documentation", operations, false));
        def.put("authorization", new ApiListingBuilder(context.getDocumentationContext().getApiDescriptionOrdering())
                .apis(apis)
                .description("Custom authentication")
                .build());

        return def;
    }

}