from flask_script import Manager
from flask_migrate import Migrate, MigrateCommand
from app import app, db, User, Role
from sqlalchemy.exc import IntegrityError
import datetime

migrate = Migrate(app, db)

manager = Manager(app)
manager.add_command('db', MigrateCommand)


def get_or_create(session, model, **kwargs):
    '''
    Creates an object or returns the object if exists
    credit to Kevin @ StackOverflow
    from: http://stackoverflow.com/questions/2546207/does-sqlalchemy-have-an-equivalent-of-djangos-get-or-create
    '''
    instance = session.query(model).filter_by(**kwargs).first()
    if instance:
        return instance
    else:
        instance = model(**kwargs)
        session.add(instance)
        return instance

from sqlalchemy import exc

@manager.command
def create_admin():
    """Creates the administrative user."""
    db.create_all()
    new_role = get_or_create(db.session, Role,
                             name="admin",
                             description="Administrative user."
                             )
    new_role1 = get_or_create(db.session, Role,
                              name="client",
                              description="Client user(user who signed up using oauth or email + password)."
                              )
    db.session.commit()

    try:
        new_user = User(
                    email="arlus@faidika.co.ke",
                    password="adminpass",
                    first_name="administrative",
                    last_name="user",
                    active=True,
                    created=datetime.datetime.now(),
                    roles=[new_role, ],
                    social_id=None
                    )
        # new_user.roles.append(new_role)
        db.session.commit()
    except exc.IntegrityError:
        db.session().rollback()


if __name__ == '__main__':
    manager.run()
