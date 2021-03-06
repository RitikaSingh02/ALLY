"""added profile_pic in users

Revision ID: b375e8bef790
Revises: b8eb264eed1e
Create Date: 2021-07-13 20:03:42.479837

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b375e8bef790'
down_revision = 'b8eb264eed1e'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('userrequests', schema=None) as batch_op:
        batch_op.add_column(sa.Column('profile_pic', sa.String(length=200), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('userrequests', schema=None) as batch_op:
        batch_op.drop_column('profile_pic')

    # ### end Alembic commands ###
