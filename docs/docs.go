// Package docs Code generated by swaggo/swag. DO NOT EDIT
package docs

import "github.com/swaggo/swag"

const docTemplate = `{
    "schemes": {{ marshal .Schemes }},
    "swagger": "2.0",
    "info": {
        "description": "{{escape .Description}}",
        "title": "{{.Title}}",
        "contact": {
            "name": "Artem Darizhapov",
            "email": "gorropand@gmail.com"
        },
        "version": "{{.Version}}"
    },
    "host": "{{.Host}}",
    "basePath": "{{.BasePath}}",
    "paths": {
        "/auth/{guid}/login": {
            "post": {
                "description": "Issues a pair of authentication tokens and sets them as cookies",
                "tags": [
                    "auth"
                ],
                "summary": "Login user",
                "parameters": [
                    {
                        "type": "string",
                        "example": "123e4567-e89b-12d3-a456-426614174000",
                        "description": "A valid user GUID",
                        "name": "guid",
                        "in": "path",
                        "required": true
                    }
                ],
                "responses": {
                    "204": {
                        "description": "No Content"
                    },
                    "400": {
                        "description": "Invalid GUID"
                    },
                    "500": {
                        "description": "Internal Server Error"
                    }
                }
            }
        },
        "/auth/{guid}/logout": {
            "post": {
                "description": "Deauthorizes client. If they are not authenticated nothing happens.",
                "tags": [
                    "auth"
                ],
                "summary": "Logout user",
                "parameters": [
                    {
                        "type": "string",
                        "example": "123e4567-e89b-12d3-a456-426614174000",
                        "description": "A valid user GUID",
                        "name": "guid",
                        "in": "path",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK"
                    }
                }
            }
        },
        "/auth/{guid}/refresh": {
            "post": {
                "description": "Refreshes access and refresh tokens if the refresh token is valid.\nDeauthorizes user if the user agent does not match to the one that issued the refresh token.",
                "tags": [
                    "auth"
                ],
                "summary": "Refresh tokens",
                "parameters": [
                    {
                        "type": "string",
                        "example": "123e4567-e89b-12d3-a456-426614174000",
                        "description": "A valid user GUID",
                        "name": "guid",
                        "in": "path",
                        "required": true
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK"
                    },
                    "401": {
                        "description": "Unauthorized"
                    },
                    "500": {
                        "description": "Internal Server Error"
                    }
                }
            }
        },
        "/security/refresh-new-ip": {
            "post": {
                "description": "Demo endpoint for a \"refresh from new IP\" action notifications",
                "consumes": [
                    "application/json"
                ],
                "tags": [
                    "security"
                ],
                "summary": "Security notification webhook",
                "parameters": [
                    {
                        "description": "Notification payload",
                        "name": "payload",
                        "in": "body",
                        "required": true,
                        "schema": {
                            "$ref": "#/definitions/routes.securityDummyWebhook.payload"
                        }
                    }
                ],
                "responses": {
                    "200": {
                        "description": "OK"
                    },
                    "400": {
                        "description": "Bad Request"
                    }
                }
            }
        },
        "/whoami": {
            "get": {
                "description": "Returns authenticated user GUID",
                "produces": [
                    "application/json"
                ],
                "tags": [
                    "user"
                ],
                "summary": "Get current user's GUID",
                "responses": {
                    "200": {
                        "description": "OK",
                        "schema": {
                            "$ref": "#/definitions/routes.whoami.resp"
                        }
                    },
                    "401": {
                        "description": "Unauthorized"
                    },
                    "500": {
                        "description": "Internal Server Error"
                    }
                }
            }
        }
    },
    "definitions": {
        "routes.securityDummyWebhook.payload": {
            "type": "object",
            "properties": {
                "new_ip": {
                    "type": "string",
                    "example": "10.0.0.1:80085"
                },
                "old_ip": {
                    "type": "string",
                    "example": "127.0.0.1:80085"
                },
                "user_agent": {
                    "type": "string",
                    "example": "useragent/10.1.1"
                },
                "user_guid": {
                    "type": "string",
                    "example": "123e4567-e89b-12d3-a456-426614174000"
                }
            }
        },
        "routes.whoami.resp": {
            "type": "object",
            "properties": {
                "GUID": {
                    "type": "string",
                    "example": "123e4567-e89b-12d3-a456-426614174000"
                }
            }
        }
    }
}`

// SwaggerInfo holds exported Swagger Info so clients can modify it
var SwaggerInfo = &swag.Spec{
	Version:          "1.0",
	Host:             "",
	BasePath:         "/",
	Schemes:          []string{},
	Title:            "Authentication JWT API",
	Description:      "JWT Authentication Assignment API",
	InfoInstanceName: "swagger",
	SwaggerTemplate:  docTemplate,
	LeftDelim:        "{{",
	RightDelim:       "}}",
}

func init() {
	swag.Register(SwaggerInfo.InstanceName(), SwaggerInfo)
}
