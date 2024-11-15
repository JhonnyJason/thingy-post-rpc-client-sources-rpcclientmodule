# ############################################################
# #region debug
# import { createLogFunctions } from "thingy-debug"
# {log, olog} = createLogFunctions("rpcpostclient")
# #endregion

############################################################
#region imports
import * as secUtl from "secret-manager-crypto-utils"
import * as validatableStamp from "validatabletimestamp"
import * as sess from "thingy-session-utils"
import * as tbut from "thingy-byte-utils"
import { FRAESC as Generator } from "feistelled-reduced-aes-core"

import {
    NOT_AUTHORIZED, NetworkError, ResponseAuthError, RPCError 
} from "./rpcerrors.js"

#endregion

############################################################
TOKEN_SIMPLE = 0
TOKEN_UNIQUE = 1
AUTHCODE_SHA2 = 2

############################################################
export class RPCPostClient
    constructor: (o) ->
        @serverURL = o.serverURL
        @serverId = o.serverId
        @serverContext = "thingy-rpc-post-connection"
        @secretKeyHex = o.secretKeyHex
        @publicKeyHex = o.publicKeyHex
        @name = "rpc-client"+randomPostfix()
        @requestId = 0
        @sessions = new Array(4)
        @anonymousToken = null
        @publicToken = null
        if o.anonymousToken? then @anonymousToken = o.anonymousToken
        if o.publicToken? then @publicToken = o.publicToken
        if o.name? then @name = o.name
        if o.serverContext? then @serverContext = o.serverContext
    
    ########################################################
    updateServer: (serverURL, serverId, serverContext) ->
        @serverURL = serverURL
        @serverId = serverId
        @serverContext = serverContext
        @requestId = 0
        @sessionInfo = {}
        return

    updateKeys: (secretKeyHex, publicKeyHex) ->
        @secretKeyHex = secretKeyHex
        @publicKeyHex = publicKeyHex
        @requestId = 0
        @sessionInfo = {}
        return

    ########################################################
    getServerURL: -> @serverURL
    getServerId: ->
        if !@serverId? then await @requestNodeId("none")
        return @serverId

    getSecretKey: -> @secretKeyHex
    getPublicKey: ->
        if !@publicKeyHex? then @publicKeyHex = await secUtl.createPublicKeyHex(@secretKeyHex)
        return @publicKeyHex

    ########################################################
    doRPC: (func, args, authType) ->
        if @requestingNodeId && func != "getNodeId" then throw new Error("Cannot do regular RPCs while requesting NodeId!")

        switch authType
            when "none" then return doNoAuthRPC(func, args, this)
            when "anonymous" then return  doAnonymousRPC(func, args, this)
            when "publicAccess" then return doPublicAccessRPC(func, args, this)
            when "tokenSimple" then return doTokenSimpleRPC(func, args, this)
            when "tokenUnique" then return doTokenUniqueRPC(func, args, this)
            when "authCodeSHA2" then return doAuthCodeSHA2RPC(func, args, this)
            when "signature", "clientSignature", "masterSignature"
                return doSignatureRPC(func, args, authType, this)
            else throw new Error("doRPC: Unknown authType! '#{authType}'")
        return

    ########################################################
    requestNodeId: (authType) ->
        @requestingNodeId = true
        func = "getNodeId"
        args =  {} 
        try await @doRPC(func, args, authType)
        finally
            @requestingNodeId = false
        return

########################################################
#region internal functions

########################################################
randomPostfix = ->
    rand = Math.random()
    return Math.round(rand * 1000)

########################################################
postRPCString = (url, requestString) ->
    options =
        method: 'POST'
        credentials: 'omit'
        body: requestString
        headers:
            'Content-Type': 'application/json'

    try
        response = await fetch(url, options)
        return await response.json()
    catch err
        baseMsg = "Error! RPC could not receive a JSON response!"
        statusText = "No http-status could be provided!"        
        try
            statusText = "HTTP-Status: #{response.status}"
            bodyText = "Body:  #{await response.text()}"
        catch err2
            details = "No response could be retrieved! details: #{err.message}"
            errorMsg = "#{baseMsg} #{statusText} #{details}" 
            throw new NetworkError(errorMsg)

        details = "#{statusText} #{bodyText}"
        errorMsg = "#{baseMsg} #{details}"
        throw new NetworkError(errorMsg)
    return

########################################################
incRequestId = (c) ->
    c.requestId = ++c.requestId % 10000000
    return

########################################################
#region RPC execution functions

########################################################
extractServerId = (response) ->
    result = response.result

    if typeof result == "object" and result.serverNodeId?
        validatableStamp.assertValidity(result.timestamp)

        nodeId = result.serverNodeId
        sig = result.signature
        result.signature = ""
        content = JSON.stringify(result)
        verified = await secUtl.verify(sig, nodeId, content)
        if !verified then throw new Error("ServerId validation Failed: Invalid Signature!")

        return nodeId

    if response.auth? and response.auth.serverId?
        return response.auth.serverId

    return ""

########################################################
doSignatureRPC = (func, args, type, c) ->
    incRequestId(c)

    clientId = await c.getPublicKey()
    requestId = c.requestId
    name = c.name
    timestamp = validatableStamp.create()
    signature = ""

    auth = { type, clientId, name, requestId, timestamp, signature }
    rpcRequest = { auth, func, args }

    serverId = await c.getServerId()
    requestString = JSON.stringify(rpcRequest)
    sigHex = await secUtl.createSignature(requestString, c.secretKeyHex)
    requestString = requestString.replace('"signature":""', '"signature":"'+sigHex+'"')
    # log requestString

    response = await postRPCString(c.serverURL, requestString)
    # olog { response }

    # in case of an error
    if response.error then throw new RPCError(func, response.error)

    if c.requestingNodeId then c.serverId = await extractServerId(response) 
    await authenticateServiceSignature(response, requestId, serverId)
    
    return response.result 

########################################################
#region public RPCs
doNoAuthRPC = (func, args, c) ->
    auth = null
    requestString = JSON.stringify({ auth, func, args })
    serverId = c.serverId

    response = await postRPCString(c.serverURL, requestString)
    # olog response
    
    if response.error then throw new RPCError(response.error)

    if c.requestingNodeId then c.serverId = await extractServerId(response) 

    return response.result 

doAnonymousRPC = (func, args, c) ->
    incRequestId(c)

    type = "anonymous"
    requestId = c.requestId
    timestamp = validatableStamp.create()
    requestToken = c.anonymousToken

    auth = { type, requestId, timestamp, requestToken }
    
    requestString = JSON.stringify({ auth, func, args })
    serverId = c.serverId

    response = await postRPCString(c.serverURL, requestString)
    # olog response
    
    if response.error then throw new RPCError(response.error)

    if c.requestingNodeId then c.serverId = await extractServerId(response) 

    return response.result 

doPublicAccessRPC = (func, args, c) ->
    incRequestId(c)

    type = "publicAccess"
    requestId = c.requestId
    clientId = await c.getPublicKey()
    timestamp = validatableStamp.create()
    requestToken = c.publicToken
    auth = { type, clientId, requestId, timestamp, requestToken }

    # olog auth

    requestString = JSON.stringify({ auth, func, args })
    serverId = c.serverId

    response = await postRPCString(c.serverURL, requestString)
    # olog response

    if response.error then throw new RPCError(response.error)

    if c.requestingNodeId then c.serverId = await extractServerId(response) 
    authenticateServiceStatement(response, requestId, serverId)

    return response.result 

#endregion

########################################################
#region session RPCs
doTokenSimpleRPC = (func, args, c) ->
    await establishSimpleTokenSession(c)    
    incRequestId(c)

    type = "tokenSimple"
    clientId = await c.getPublicKey()
    requestId = c.requestId
    name = c.name
    timestamp = validatableStamp.create()
    requestToken = c.sessions[TOKEN_SIMPLE].token

    auth = { type, clientId, name, requestId, timestamp, requestToken }
    rpcRequest = { auth, func, args }
    requestString = JSON.stringify(rpcRequest)

    serverId = await c.getServerId()
    response = await postRPCString(c.serverURL, requestString)
    # olog { response }

    # in case of an error
    if response.error
        corruptSession = response.error.code? and response.error.code == NOT_AUTHORIZED
        if corruptSession then c.sessions[TOKEN_SIMPLE] = null
        throw new RPCError(func, response.error)

    if c.requestingNodeId then c.serverId = await extractServerId(response) 
    await authenticateServiceStatement(response, requestId, serverId)

    return response.result 

doTokenUniqueRPC  = (func, args, c) ->
    throw new Error("doTokenUniqueRPC: Not Implemented yet!")
    await establishUniqueTokenSession(c)
    incRequestId(c)

    type = "tokenUnique"
    clientId = await c.getPublicKey()
    requestId = c.requestId
    name = c.name
    timestamp = validatableStamp.create()
    uniqueBytes = c.sessions[TOKEN_UNIQUE].generator.generate(timestamp)
    requestToken = tbut.bytesToHex(uniqueBytes)

    auth = { type, clientId, name, requestId, timestamp, requestToken }
    rpcRequest = { auth, func, args }
    requestString = JSON.stringify(rpcRequest)

    serverId = await c.getServerId()
    response = await postRPCString(c.serverURL, requestString)
    # olog { response }

    # in case of an error
    if response.error
        corruptSession = response.error.code? and response.error.code == NOT_AUTHORIZED
        if corruptSession then c.sessions[TOKEN_UNIQUE] = null
        throw new RPCError(func, response.error)

    if c.requestingNodeId then c.serverId = await extractServerId(response) 
    await authenticateServiceStatement(response, requestId, serverId)

    return response.result 

doAuthCodeSHA2RPC = (func, args, c) ->
    await establishSHA2AuthCodeSession(c)    
    incRequestId(c)

    session = c.sessions[AUTHCODE_SHA2]

    type = "authCodeSHA2"
    clientId = await c.getPublicKey()
    requestId = c.requestId
    name = c.name
    timestamp = validatableStamp.create()
    requestAuthCode = ""

    auth = { type, clientId, name, requestId, timestamp, requestAuthCode }
    rpcRequest = { auth, func, args }

    serverId = await c.getServerId()
    requestString = JSON.stringify(rpcRequest)
    authCode = await sess.createAuthCode(session.seedHex, requestString)
    requestString = requestString.replace('"requestAuthCode":""', '"requestAuthCode":"'+authCode+'"')
    # log requestString

    response = await postRPCString(c.serverURL, requestString)
    # olog { response }

    # in case of an error
    if response.error
        corruptSession = response.error.code? and response.error.code == NOT_AUTHORIZED
        if corruptSession then c.sessions[AUTHCODE_SHA2] = null
        throw new RPCError(func, response.error)

    if c.requestingNodeId then c.serverId = await extractServerId(response) 
    await authenticateServiceAuthCodeSHA2(response, requestId, serverId, c)
    
    return response.result 

#endregion

#endregion

############################################################
#region session establishment
startSessionExplicitly = (type, c) ->
    incRequestId(c)

    name = c.name
    args = { type, name }
    
    func = "startSession"
    authType = "clientSignature"
    try return await c.doRPC(func, args, authType)
    catch err then throw new Error("Explicit Start failed: #{err.message}")
    return

establishSimpleTokenSession = (c) ->
    if c.sessions[TOKEN_SIMPLE]? and c.sessions[TOKEN_SIMPLE].token? then return
    try
        session = {}
        session.token = await getExplicitSimpleToken(c)
        # if c.implicitSessions
        #     session.token = await generateImplicitSimpleToken(c)
        # else
        #     session.token = await getExplicitSimpleToken(c)
        c.sessions[TOKEN_SIMPLE] = session
    catch err
        message = "Could not establish a simple Token session! Details: #{err.message}"
        throw new Error(message)
    return

generateSharedSecretSeed = (timestamp, c) ->
    serverContext = c.serverContext
    specificContext = c.name
    context = "#{specificContext}:#{serverContext}_#{timestamp}"
    return await secUtl.diffieHellmanSecretHashHex(c.secretKeyHex, c.serverId, context)

getExplicitSimpleToken = (c) ->
    return startSessionExplicitly("tokenSimple", c)

establishUniqueTokenSession = (c) ->
    if c.sessions[TOKEN_UNIQUE]? and c.sessions[TOKEN_UNIQUE].seedHex? then return
    try
        session = {}
        timestamp = await startSessionExplicitly("tokenUnique", c)
        seedBytes = tbut.hexToBytes(await generateSharedSecretSeed(timestamp, c))
        session.generator = new Generator(seedBytes)
        
        c.sessions[TOKEN_UNIQUE] = session
    catch err
        message = "Could not establish a unique Token session! Details: #{err.message}"
        throw new Error(message)
    return

establishSHA2AuthCodeSession = (c) ->
    if c.sessions[AUTHCODE_SHA2]? and c.sessions[AUTHCODE_SHA2].seedHex? then return
    try
        session = {}
        timestamp = await startSessionExplicitly("authCodeSHA2", c)
        session.seedHex = await generateSharedSecretSeed(timestamp, c)

        c.sessions[AUTHCODE_SHA2] = session
    catch err
        message = "Could not establish an authCode with SHA2 session! Details: #{err.message}"
        throw new Error(message)
    return

#endregion

############################################################
#region response Authentication
authenticateServiceSignature = (response, ourRequestId, ourServerId) ->
    try
        signature = response.auth.signature
        timestamp = response.auth.timestamp
        requestId = response.auth.requestId
        serverId = response.auth.serverId
        
        if !signature? then throw new Error("No Signature!")
        if !timestamp? then throw new Error("No Timestamp!")
        if !requestId? then throw new Error("No RequestId!")
        if !serverId? then throw new Error("No ServerId!")
        
        if requestId != ourRequestId then throw new Error("RequestId Mismatch!")
        if serverId != ourServerId then throw new Error("ServerId Mismatch!")
        
        validatableStamp.assertValidity(timestamp)
        
        response.auth.signature = ""
        responseString = JSON.stringify(response)
        verified = await secUtl.verify(signature, serverId, responseString)
        if !verified then throw new Error("Invalid Signature!")

    catch err then throw new ResponseAuthError(err.message)
    return

authenticateServiceStatement = (response, ourRequestId, ourServerId) ->
    try
        timestamp = response.auth.timestamp
        requestId = response.auth.requestId
        serverId = response.auth.serverId
        
        if !timestamp? then throw new Error("No Timestamp!")
        if !requestId? then throw new Error("No RequestId!")
        if !serverId? then throw new Error("No ServerId!")
        
        if requestId != ourRequestId then throw new Error("RequestId Mismatch!")
        if serverId != ourServerId then throw new Error("ServerId Mismatch!")
        
        validatableStamp.assertValidity(timestamp)
        
    catch err then throw new ResponseAuthError(err.message)
    return

authenticateServiceAuthCodeSHA2 = (response, ourRequestId, ourServerId, c) ->
    try
        responseAuthCode = response.auth.responseAuthCode
        timestamp = response.auth.timestamp
        requestId = response.auth.requestId
        serverId = response.auth.serverId
        
        if !responseAuthCode? then throw new Error("No ResponseAuthCode!")
        if !timestamp? then throw new Error("No Timestamp!")
        if !requestId? then throw new Error("No RequestId!")
        if !serverId? then throw new Error("No ServerId!")
        
        if requestId != ourRequestId then throw new Error("RequestId Mismatch!")
        if serverId != ourServerId then throw new Error("ServerId Mismatch!")
        
        validatableStamp.assertValidity(timestamp)
        
        session = c.sessions[AUTHCODE_SHA2]
        if !session? or !session.seedHex? then throw new Error("Local session object has become invalid!")
        response.auth.responseAuthCode = ""
        responseString = JSON.stringify(response)
        # log responseString
        authCode = await sess.createAuthCode(session.seedHex, responseString)
        # olog { authCode, responseAuthCode }
        
        if authCode != responseAuthCode then throw new Error("AuthCodes did not Match!")
    catch err then throw new ResponseAuthError("authenticateServiceAuthCodeSHA2: #{err.message}")
    return

#endregion

#endregion
