"""added profile_pic in users

Revision ID: b068e92d5b01
Revises: 1fceccac2327
Create Date: 2021-07-13 20:23:02.390603

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b068e92d5b01'
down_revision = '1fceccac2327'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('userrequests', schema=None) as batch_op:
        batch_op.add_column(sa.Column('acc_holder_name', sa.String(length=200), nullable=True))
        batch_op.add_column(sa.Column('phone', sa.String(length=200), nullable=True))
        batch_op.add_column(sa.Column('ifsc', sa.String(length=200), nullable=True))
        batch_op.add_column(sa.Column('acc_no', sa.String(length=200), nullable=True))
        batch_op.add_column(sa.Column('upi_id', sa.String(length=200), nullable=True))
        batch_op.add_column(sa.Column('gpay', sa.String(length=200), nullable=True))
        batch_op.add_column(sa.Column('amazon_pay', sa.String(length=200), nullable=True))
        batch_op.add_column(sa.Column('paytm', sa.String(length=200), nullable=True))
        batch_op.add_column(sa.Column('phone_pay', sa.String(length=200), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('userrequests', schema=None) as batch_op:
        batch_op.drop_column('phone_pay')
        batch_op.drop_column('paytm')
        batch_op.drop_column('amazon_pay')
        batch_op.drop_column('gpay')
        batch_op.drop_column('upi_id')
        batch_op.drop_column('acc_no')
        batch_op.drop_column('ifsc')
        batch_op.drop_column('phone')
        batch_op.drop_column('acc_holder_name')

    # ### end Alembic commands ###
