############################################################
export PARSE_ERROR = -32700
export INVALID_REQUEST = -32600
export METHOD_NOT_FOUND = -32601
export NOT_AUTHORIZED = -32023
export NO_SEATS = -32002
export INVALID_PARAMS = -32602
export EXECUTION_ERROR = -32032

############################################################
rpcErrorMap = new Map()

############################################################
#region Error message For RPC Errors

############################################################
rpcErrorMap.set(
    PARSE_ERROR, 
    {
        message: "JSON Parse Error!"
    }
)

############################################################
rpcErrorMap.set(
    INVALID_REQUEST, 
    {
        message: "Request is invalid thingy-rpc!"
    }
)

############################################################
rpcErrorMap.set(
    METHOD_NOT_FOUND, 
    {
        message: "Method not found!"
    }
)

############################################################
rpcErrorMap.set(
    NOT_AUTHORIZED, 
    {
        message: "Authentication failed!"
    }
)

############################################################
rpcErrorMap.set(
    NO_SEATS, 
    {
        message: "No free ressources available on the server!"
    }
)

############################################################
rpcErrorMap.set(
    INVALID_PARAMS, 
    {
        message: "Invalid params provided!"
    }
)

############################################################
rpcErrorMap.set(
    EXECUTION_ERROR, 
    {
        message: "Execution error!"
    }
)

#endregion

############################################################
export class NetworkError extends Error
    constructor: (message) ->
        super(message)
        @name = "NetworkError"

############################################################
export class ResponseAuthError extends Error
    constructor: (message) ->
        super(message)
        @name = "ResponseAuthError"

############################################################
export class RPCError extends Error
    constructor: (func, remoteError) ->
        console.log JSON.stringify(remoteError, null, 4)
        errorCode = remoteError.code
        error = rpcErrorMap.get(errorCode)
        super("#{func}: #{error.message} (#{remoteError.message})")
        @rpcCode = errorCode
        @name = "RPCError"