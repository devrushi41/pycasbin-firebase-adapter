Firebase Adapter for PyCasbin 
====

Firebase Adapter is the [Firebase](https://firebase.google.com/) adapter for [PyCasbin](https://github.com/casbin/pycasbin). With this library, Casbin can load policy from Firebase Firestore or save policy to it.


## Installation

```
pip install pycasbin_firebase_adapter
```

## Simple Example

```python
import pycasbin_firebase_adapter
import casbin

adapter = pycasbin_firebase_adapter.Adapter('path/to/services.json')

e = casbin.Enforcer('path/to/model.conf', adapter)

sub = "alice"  # the user that wants to access a resource.
obj = "data1"  # the resource that is going to be accessed.
act = "read"  # the operation that the user performs on the resource.

if e.enforce(sub, obj, act):
    # permit alice to read data1
    pass
else:
    # deny the request, show an error
    pass
```

### Credits

Based on [sqlalchemy-adapter](https://github.com/pycasbin/sqlalchemy-adapter)


### Getting Help

- [PyCasbin](https://github.com/casbin/pycasbin)

### License

This project is licensed under the [Apache 2.0 license](LICENSE).