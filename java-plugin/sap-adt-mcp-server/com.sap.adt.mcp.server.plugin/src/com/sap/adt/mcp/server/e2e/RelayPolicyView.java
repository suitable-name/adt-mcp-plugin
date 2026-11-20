package com.sap.adt.mcp.server.e2e;

import com.google.gson.JsonArray;

/** The relay's policy as attached to a forwarded request frame ({@code allowedTools}, {@code packageScopes}). */
public record RelayPolicyView(java.util.List<String> allowedTools, com.google.gson.JsonArray packageScopes) {
}
