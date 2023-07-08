try:
    from fastapi import FastAPI

    # Get all global objects
    globals_objects = globals().values()

    # Find an instance of FastAPI
    for obj in globals_objects:
        if isinstance(obj, FastAPI):
            # Add your router to the existing FastAPI instance
            from fastapi import APIRouter
            from . import router

            app = obj
            app.include_router(router.authorization)
            break

except ImportError:
    pass
