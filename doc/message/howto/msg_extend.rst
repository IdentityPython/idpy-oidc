.. _oidcmsg_extend:

How to extend message
=====================

By extending I mean adding a new message class.
In most case starting with an existing class is probably the way to go.

Let's assume that we want to add one claim to an ErrorResponse.
The claim are supposed to be *error_status* and the values of type integer.

The resulting class could look like this::

    class StatusErrorResponse(ErrorResponse):
        """
        Error response with status code.
        """
        c_param = ErrorResponse.c_param.copy()
        c_param.update({"status": SINGLE_REQUIRED_INT})

        def verify(self, **kwargs):
            super(StatusErrorResponse, self).verify(**kwargs)

            if 200 <= self['status'] <= 600:
                pass
            else:
                raise ValueError('status outside allowed value space')

Taken line by line::

    class StatusErrorResponse(ErrorResponse):

StatusErrorResponse is a sub class of ErrorResponse::

            c_param = ErrorResponse.c_param.copy()

All the claims that are connected to an ErrorResponse are here inherited
by the StatusErrorResponse class::

            c_param.update({"status": SINGLE_REQUIRED_INT})

Adds only one claim and that claim is required and of type integer.
There are a number of predefined specifications like this one ready
to be used.

- SINGLE_OPTIONAL_STRING
- SINGLE_REQUIRED_STRING
- SINGLE_OPTIONAL_INT
- SINGLE_REQUIRED_INT
- OPTIONAL_LIST_OF_STRINGS
- REQUIRED_LIST_OF_STRINGS
- OPTIONAL_LIST_OF_SP_SEP_STRINGS
- REQUIRED_LIST_OF_SP_SEP_STRINGS
- SINGLE_OPTIONAL_JSON
- OPTIONAL_MESSAGE
- REQUIRED_MESSAGE
- OPTIONAL_LIST_OF_MESSAGES

All these specifications follow the same pattern, being a tuple of these
parts:

- value type
- required
- serializer
- deserializer
- null allowed as value

Next is the verify method::

        def verify(self, **kwargs):
            super(StatusErrorResponse, self).verify(**kwargs)

            if 200 <= self['status'] <= 600:
                pass
            else:
                raise ValueError('status outside allowed value space')

Here running the super classes verify method first makes sense because
it means all claims will be checked to comply with the value specification
before we continue with the specific checks belonging to this class.
For instance in this case we can be sure the self['status'] has a value
and that the value is an integer. So we don't have to check for that.
