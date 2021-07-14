"""added FK in userrequests table

Revision ID: d999179632e8
Revises: d992f4a01fc1
Create Date: 2021-07-14 17:58:14.299468

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd999179632e8'
down_revision = 'd992f4a01fc1'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('userrequests', schema=None) as batch_op:
        batch_op.add_column(sa.Column('title', sa.String(length=200), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('userrequests', schema=None) as batch_op:
        batch_op.drop_column('title')

    # ### end Alembic commands ###