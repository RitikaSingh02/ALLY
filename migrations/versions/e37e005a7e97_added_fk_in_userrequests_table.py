"""added FK in userrequests table

Revision ID: e37e005a7e97
Revises: d999179632e8
Create Date: 2021-07-14 18:13:09.770286

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e37e005a7e97'
down_revision = 'd999179632e8'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('userrequests', schema=None) as batch_op:
        batch_op.add_column(sa.Column('status', sa.String(length=200), nullable=False))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('userrequests', schema=None) as batch_op:
        batch_op.drop_column('status')

    # ### end Alembic commands ###
