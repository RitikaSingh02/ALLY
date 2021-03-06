"""added FK in userrequests table

Revision ID: ce1c401771b7
Revises: 08c4170b9226
Create Date: 2021-07-13 20:30:22.883236

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import mysql

# revision identifiers, used by Alembic.
revision = 'ce1c401771b7'
down_revision = '08c4170b9226'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('userrequests', schema=None) as batch_op:
        batch_op.drop_column('request_type')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('userrequests', schema=None) as batch_op:
        batch_op.add_column(sa.Column('request_type', mysql.VARCHAR(length=200), nullable=False))

    # ### end Alembic commands ###
